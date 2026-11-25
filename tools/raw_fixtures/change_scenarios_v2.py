"""Materialize deterministic source-shaped facts for the two change demos.

This module is deliberately offline.  It resolves the identities declared by a
scenario template and returns HEC envelopes plus uncollected native API inputs.
It never sends data, creates Splunk graph/search rows, or claims a collection,
indexed receipt, event fingerprint, permission check, or effective time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid
from collections import Counter
from typing import Any

from tools.change_correlation.contracts import canonical_json
from tools.raw_fixtures.common import NS, envelope, epoch
from tools.raw_fixtures.nxos import aci_event


def aci_endpoint_snapshot_event(*, event_host: str, emitted_at: datetime,
                                apic_host: str, endpoint_dn: str,
                                fabric_path_dn: str, encapsulation: str,
                                learning_classification: str, ownership: str) -> dict:
    """Build the v2 offline ACI endpoint fact without changing v1 fixtures."""
    values = (event_host, apic_host, endpoint_dn, fabric_path_dn, encapsulation,
              learning_classification, ownership)
    if emitted_at.tzinfo is None or any(not isinstance(v, str) or not v.strip() for v in values):
        raise ValueError("ACI endpoint fixture inputs are invalid.")
    attributes = sorted([
        ("dn", endpoint_dn), ("fabricPathDn", fabric_path_dn),
        ("encap", encapsulation), ("lcC", learning_classification),
        ("lcOwn", ownership),
    ])
    return envelope(epoch(emitted_at), event_host,
                    "cisco_nexus_aci://classInfo_faultInst", "cisco:dc:aci:class",
                    "cisco_dc", aci_event(emitted_at, attributes, apic_host, "fvCEp"))


SOURCE_PROVENANCE = "documentation_shaped_synthetic"
SOURCE_PACKAGE_KIND = "change_scenario_source_facts_v1"
SCENARIO_IDS = ("track-a-firewall", "track-b-fabric")
HEAVY_FORWARDER = "splunk-hf-01"
STREAM_FORWARDER = "stream-fwd-01"
HUBBLE_FILE = "/var/run/cilium/hubble/events.log"
PROFILE_KEY = (
    "source",
    "source_authority",
    "domain_kind",
    "observation_domain_present",
    "observation_domain_id",
    "vpn_id",
    "routing_domain",
)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_RECIPE_KEYS = {
    "_indextime",
    "indexed_receipt_epoch",
    "event_fingerprint",
    "event_id",
    "effective_at",
    "received_at",
    "permissions_fingerprint",
    "capture_id",
}


class SourceMaterializationError(ValueError):
    """A malformed template, plan, identity or duplicate route mapping."""


class _MissingFact(ValueError):
    """One schedule item cannot be emitted without an undeclared source fact."""


def _sha256(value: bytes | Any) -> str:
    body = value if isinstance(value, bytes) else canonical_json(value)
    return hashlib.sha256(body).hexdigest()


def _stable_hex(*parts: object, length: int = 64) -> str:
    material = "|".join(map(str, parts)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:length]


def _stable_int(*parts: object, modulus: int = 10**9) -> int:
    return int(_stable_hex(*parts, length=16), 16) % modulus


def _json_array(values: Sequence[object]) -> str:
    """Match the compact JSON-array spelling used by the Splunk lookup writer."""

    return json.dumps([str(value) for value in values], separators=(",", ":"))


def _utc(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _iso(epoch: int, precision: str = "us") -> str:
    value = _utc(epoch)
    if precision == "s":
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if precision == "ms":
        return (
            value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
        )
    if precision == "offset_ms":
        return (
            value.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{value.microsecond // 1000:03d}+00:00"
        )
    if precision == "proto":
        if not value.microsecond:
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")
        if value.microsecond % 1000 == 0:
            return (
                value.strftime("%Y-%m-%dT%H:%M:%S.")
                + f"{value.microsecond // 1000:03d}Z"
            )
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if precision == "us":
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    raise SourceMaterializationError("Unsupported source timestamp precision.")


def _event_time(event: Mapping[str, Any]) -> int:
    value = event.get("planned_source_epoch")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _MissingFact("scheduled source time is unavailable")
    return value


def _require_map(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceMaterializationError(f"{path} must be an object.")
    return value


def _require_text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _MissingFact(f"{path} is missing or empty")
    return value.strip()


def _identity_value(scenario_id: str, descriptor: Mapping[str, Any], path: str) -> str:
    strategy = descriptor.get("strategy")
    logical_key = descriptor.get("logical_key")
    if (
        not isinstance(strategy, str)
        or not isinstance(logical_key, str)
        or not logical_key
    ):
        raise SourceMaterializationError(f"Identity descriptor at {path} is invalid.")
    digest = _stable_hex(scenario_id, logical_key)
    if strategy == "synthetic_numeric_sha256_v1":
        # Positive decimal organization IDs match the Dashboard API's text ID form.
        return str(100_000_000_000 + int(digest[:12], 16) % 800_000_000_000)
    if strategy == "meraki_N_decimal_sha256_v1":
        return f"N_{int(digest[:12], 16) % 10**12:012d}"
    if strategy == "meraki_Q2XX_serial_sha256_v1":
        # Meraki serial-shaped synthetic value: Q2XX-XXXX-XXXX.
        material = digest[:10].upper()
        return f"Q2{material[:2]}-{material[2:6]}-{material[6:10]}"
    if strategy == "nxos_FDO_serial_sha256_v1":
        return f"FDO{digest[:12].upper()}"
    if strategy == "uuid5_scenario_logical_key_v1":
        return str(uuid.uuid5(NS, f"{scenario_id}:{logical_key}"))
    raise SourceMaterializationError(f"Unsupported identity strategy at {path}.")


def materialize_identity_registry(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve only declared IDs; logical aliases remain aliases in the result."""

    scenario_id = _require_text(scenario.get("scenario_id"), "scenario_id")
    original = deepcopy(
        _require_map(scenario.get("identity_registry"), "identity_registry")
    )

    def visit(value: Any, path: str) -> Any:
        if isinstance(value, Mapping):
            if set(value) == {"strategy", "logical_key"}:
                return _identity_value(scenario_id, value, path)
            result: dict[str, Any] = {}
            for key, item in value.items():
                if key in {"serial_strategy", "uid_strategy"}:
                    target = "serial" if key == "serial_strategy" else "uid"
                    result[target] = _identity_value(
                        scenario_id,
                        {"strategy": item, "logical_key": value.get("logical_key")},
                        f"{path}.{key}",
                    )
                else:
                    result[key] = visit(item, f"{path}.{key}")
            return result
        if isinstance(value, list):
            return [visit(item, f"{path}[{index}]") for index, item in enumerate(value)]
        return value

    registry = visit(original, "identity_registry")
    kubernetes_ids: dict[str, dict[str, str]] = {}

    def collect_kubernetes(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        logical_key = value.get("logical_key")
        if isinstance(logical_key, str) and logical_key.startswith(
            ("service.", "workload.", "node.")
        ):
            kubernetes_ids[logical_key] = {
                "uid": str(uuid.uuid5(NS, f"{scenario_id}:{logical_key}:uid")),
                "replica_set_uid": str(
                    uuid.uuid5(NS, f"{scenario_id}:{logical_key}:replicaset")
                ),
                "endpointslice_uid": str(
                    uuid.uuid5(NS, f"{scenario_id}:{logical_key}:endpointslice")
                ),
                "pod_template_hash": _stable_hex(scenario_id, logical_key, length=10),
            }
        for child in value.values():
            if isinstance(child, Mapping):
                collect_kubernetes(child)
            elif isinstance(child, list):
                for item in child:
                    collect_kubernetes(item)

    collect_kubernetes(original)
    registry["materialized_kubernetes_ids"] = kubernetes_ids
    return registry


def _source_profile(
    source: str,
    authority: str,
    domain_kind: str,
    observation_domain_present: str,
    observation_domain_id: str,
    vpn_id: str,
    routing_domain: str,
    scope: str,
    cluster: str,
    profile: str,
) -> dict[str, str | int]:
    row: dict[str, str | int] = {
        "source": source,
        "source_authority": authority,
        "domain_kind": domain_kind,
        "observation_domain_present": observation_domain_present,
        "observation_domain_id": observation_domain_id,
        "vpn_id": vpn_id,
        "routing_domain": routing_domain,
        "scope": scope,
        "cluster": cluster,
        "mapping_status": "mapped",
        "profile": profile,
    }
    mapping_key = _sha256(_json_array([str(row[key]) for key in PROFILE_KEY]).encode())
    row["mapping_key"] = mapping_key
    row["duplicate_count"] = 1
    row["_key"] = _sha256(
        _json_array([mapping_key, scope, cluster, profile, "mapped"]).encode()
    )
    return row


def _observer(kind: str, observer: str, scope: str, cluster: str) -> dict[str, str]:
    # The lookup writers normalize observer keys before persistence.
    normalized_kind, normalized_observer = kind.lower(), observer.lower()
    return {
        "observer_kind": normalized_kind,
        "observer": normalized_observer,
        "scope": scope,
        "cluster": cluster,
        "mapping_status": "verified",
        "_key": _sha256(_json_array([normalized_kind, normalized_observer]).encode()),
    }


def build_source_profiles(
    scenario: Mapping[str, Any], registry: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Build exact seven-dimension source profiles and native observer mappings."""

    scenario_id = _require_text(scenario.get("scenario_id"), "scenario_id")
    registry = registry or materialize_identity_registry(scenario)
    profiles: list[dict[str, Any]] = []
    observers: list[dict[str, str]] = []
    meraki = registry.get("meraki", {})
    if meraki:
        org_id = str(meraki["organization_id"])
        network_specs = [
            ("primary_network_id", "change-a", "cc-a-cilium"),
            ("control_network_id", "change-a-control", "cc-a-control"),
            ("unrelated_network_id", "change-a-other", "cc-a-other"),
        ]
        roots = scenario.get("identity_registry", {})
        scope_labels = {
            "primary_network_id": roots.get("primary", {}).get(
                "routing_scope", "change-a"
            ),
            "control_network_id": roots.get("control", {}).get(
                "routing_scope", "change-a-control"
            ),
            "unrelated_network_id": scenario.get("selection", {}).get(
                "unrelated_scope", "change-a-other"
            ),
        }
        cluster_labels = {
            "primary_network_id": roots.get("primary", {}).get(
                "cluster", "cc-a-cilium"
            ),
            "control_network_id": roots.get("control", {}).get(
                "cluster", "cc-a-control"
            ),
            "unrelated_network_id": scenario.get("selection", {}).get(
                "unrelated_cluster", "cc-a-other"
            ),
        }
        for key, default_scope, default_cluster in network_specs:
            network_id = meraki.get(key)
            if not network_id:
                continue
            scope = str(scope_labels.get(key) or default_scope)
            cluster = str(cluster_labels.get(key) or default_cluster)
            authority = _json_array([org_id, str(network_id)])
            profiles.append(
                _source_profile(
                    "meraki_association",
                    authority,
                    "network",
                    "0",
                    "",
                    "",
                    str(network_id),
                    scope,
                    cluster,
                    "meraki_association",
                )
            )
            observers.append(_observer("network_authority", authority, scope, cluster))

    if scenario_id == "track-b-fabric" and registry.get("catalyst"):
        catalyst = registry["catalyst"]
        profiles.append(
            _source_profile(
                "catalyst_client_snapshot",
                str(catalyst["authority"]),
                "controller",
                "0",
                "",
                "",
                "",  # This native client snapshot contains no siteId.
                "change-b",
                "cc-b-cilium",
                "catalyst_client_snapshot",
            )
        )

    for exporter in registry.get("stream_exporters", []):
        address = _require_text(
            exporter.get("address"), "stream_exporter.address"
        ).lower()
        has_domain = "observation_domain_id" in exporter
        domain_id = str(exporter.get("observation_domain_id", ""))
        vpn_id = str(exporter.get("vpn_id", ""))
        routing_domain = str(exporter.get("routing_domain", ""))
        profiles.append(
            _source_profile(
                "stream_ipfix",
                address,
                "exporter",
                "1" if has_domain else "0",
                domain_id,
                vpn_id,
                routing_domain,
                str(exporter["scope"]),
                str(exporter["cluster"]),
                str(exporter["profile"]),
            )
        )
        observers.append(
            _observer(
                "exporter", address, str(exporter["scope"]), str(exporter["cluster"])
            )
        )

    for item in registry.get("cilium_observers", []):
        observers.append(
            _observer(
                str(item["observer_kind"]),
                str(item["observer"]),
                str(item["scope"]),
                str(item["cluster"]),
            )
        )

    firewall = registry.get("firewall")
    if firewall:
        observers.append(
            _observer("firewall", str(firewall["device_ip"]), "change-a", "cc-a-cilium")
        )
    control_firewall = registry.get("control_firewall")
    if control_firewall:
        observers.append(
            _observer(
                "firewall",
                str(control_firewall["device_ip"]),
                "change-a-control",
                "cc-a-control",
            )
        )

    fabric = registry.get("fabric")
    if fabric:
        observer = _json_array([HEAVY_FORWARDER, str(fabric["chassis_serial"])])
        observers.append(_observer("nxos_serial", observer, "change-a", "cc-a-cilium"))

    aci = registry.get("aci")
    if aci:
        apic_host = str(aci["authority"]).removeprefix("https://").split("/", 1)[0]
        observers.append(_observer("apic", apic_host, "change-b", "cc-b-cilium"))
        observers.append(
            _observer(
                "acl_leaf",
                f"pod-{aci['pod_id']}/node-{aci['leaf_node_id']}",
                "change-b",
                "cc-b-cilium",
            )
        )

    nd = registry.get("nd")
    if nd:
        # ND is a separate authority from the campus/SD-WAN IPFIX sidechannel.
        # Keep the mapping explicit; no observer is inferred from an IP range.
        observers.append(
            _observer(
                "nd_host",
                str(nd["authority"]),
                "change-b",
                "cc-b-cilium",
            )
        )
        observers.append(
            _observer(
                "fabric",
                str(nd["fabric"]),
                "change-b",
                "cc-b-cilium",
            )
        )

    profile_index: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in profiles:
        key = tuple(str(row[name]) for name in PROFILE_KEY)
        if key in profile_index:
            raise SourceMaterializationError(
                "Duplicate exact seven-key network source-scope mapping."
            )
        profile_index[key] = row

    observer_index: dict[tuple[str, str], dict[str, str]] = {}
    for row in observers:
        key = (row["observer_kind"], row["observer"])
        if key in observer_index:
            raise SourceMaterializationError(
                "Duplicate native observer-scope mapping; resolve it in the template."
            )
        observer_index[key] = row

    return {
        "basis": "explicit_synthetic_administrator_configuration",
        "description": (
            "Mappings are explicit synthetic administrator configuration. "
            "They are never inferred from IP ranges or resource labels."
        ),
        "source_field_semantics": {
            "network_source_scope.source": (
                "ADM normalized source discriminator selected by the reviewed macro; "
                "it is not indexed HEC metadata source."
            ),
            "hec_source": (
                "The exact indexed HEC metadata source is retained per raw readback expectation."
            ),
            "native_payload_source": (
                "Any native source field such as FTD SourceHost remains unchanged in the payload."
            ),
        },
        "network_source_scope": [profile_index[key] for key in sorted(profile_index)],
        "observer_scope": [observer_index[key] for key in sorted(observer_index)],
    }


def _envelope(
    time: int | float,
    host: str,
    source: str,
    sourcetype: str,
    index: str,
    event: Any,
    fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "time": time,
        "host": host,
        "source": source,
        "sourcetype": sourcetype,
        "index": index,
        "event": event,
    }
    if fields:
        result["fields"] = dict(fields)
    return result


def _native_input(
    adapter: str,
    product: str,
    family: str,
    authority: str,
    partition: str,
    scope: str,
    native_payload: Any,
) -> dict[str, Any]:
    if product == "kubernetes":
        payload_format = {
            "service_snapshot": "kubernetes_v1_ServiceList",
            "endpointslice_snapshot": "kubernetes_discovery_v1_EndpointSliceList",
            "pod_snapshot": "kubernetes_v1_PodList",
        }[family]
    elif product == "aci" and family == "aaa_mod_lr":
        payload_format = "apic_aaaModLR_imdata_records"
    elif product == "aci" and family == "endpoint_state_snapshot":
        payload_format = "apic_ta_fvCEp_flattened_records"
    elif product == "aci":
        payload_format = "apic_class_imdata_records"
    elif product == "meraki":
        payload_format = "meraki_dashboard_api_record_array"
    elif product == "sdwan":
        payload_format = "catalyst_sdwan_AuditLogEntry_array"
    else:  # pragma: no cover - every caller is fixed in this module
        raise SourceMaterializationError(
            "No native payload format is declared for this adapter."
        )
    native_ids = _native_payload_ids(native_payload)
    record_count = _native_record_count(native_payload)
    return {
        "adapter": adapter,
        "input_kind": "native_api_response",
        "payload_format": payload_format,
        "product": product,
        "family": family,
        "authority": authority,
        "partition": partition,
        "scope": scope,
        "native_payload": native_payload,
        "expected_native_record_count": record_count,
        "expected_native_ids": native_ids,
        "expected_collection_shape": {
            "schema_version": 1,
            "product": product,
            "family": family,
            "authority": authority,
            "partition": partition,
            "scope": scope,
            "source_version": "documentation-shaped-synthetic-v1",
            "enumeration": "incremental",
            "expected_page_count": 1,
            "deletions_authoritative": False,
            "source_reference": "documentation-shaped-synthetic",
        },
        "native_payload_sha256": _payload_sha256(native_payload),
        "native_payload_sha256_algorithm": "native-json-sort-keys-v1",
        "provenance": SOURCE_PROVENANCE,
    }


def _readback_key(
    execution_id: str, schedule_id: str, channel: str, ordinal: int
) -> str:
    return f"change-scenario:{execution_id}:{schedule_id}:{channel}:{ordinal:04d}"


def native_payload_bytes(value: Any, algorithm: str | None = None) -> bytes:
    """Versioned raw-source serialization, separate from normalized history JSON."""
    selected = algorithm or (
        "utf8-raw-v1" if isinstance(value, str) else "native-json-sort-keys-v1"
    )
    if selected == "utf8-raw-v1" and isinstance(value, str):
        return value.encode("utf-8")
    if selected == "native-json-sort-keys-v1" and not isinstance(value, str):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    raise SourceMaterializationError(
        "Unsupported native payload hash algorithm or shape."
    )


def native_payload_sha256(value: Any, algorithm: str | None = None) -> str:
    """Preserve native int64 Unix-ns values without normalized-number rounding."""
    return hashlib.sha256(native_payload_bytes(value, algorithm)).hexdigest()


def _payload_sha256(value: Any) -> str:
    return native_payload_sha256(value)


def _native_payload_ids(value: Any) -> list[str]:
    """Collect native API object identifiers without expanding logical aliases."""

    found: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            metadata = item.get("metadata")
            if isinstance(metadata, Mapping):
                uid = metadata.get("uid")
                if isinstance(uid, str) and uid:
                    found.add(uid)
            for key in ("dn", "logid", "serial"):
                identity = item.get(key)
                if isinstance(identity, str) and identity:
                    found.add(identity)
            attributes = item.get("attributes")
            if isinstance(attributes, Mapping):
                for key in ("dn", "id"):
                    identity = attributes.get(key)
                    if isinstance(identity, str) and identity:
                        found.add(identity)
            for child in item.values():
                if isinstance(child, (Mapping, list)):
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return sorted(found)


def _native_record_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, Mapping):
        items = value.get("items")
        if isinstance(items, list):
            return len(items)
    return 1


def _decorate_native_inputs(
    native_inputs: list[dict[str, Any]], execution_id: str, schedule_id: str
) -> list[dict[str, Any]]:
    for ordinal, item in enumerate(native_inputs, start=1):
        item["readback_key"] = _readback_key(
            execution_id, schedule_id, "native", ordinal
        )
        item["expected_collection_shape"]["source_reference"] = (
            f"documentation-shaped-synthetic:{schedule_id}:{ordinal}"
        )
    return native_inputs


def _ssid_record(registry: Mapping[str, Any], vlan_key: str) -> list[dict[str, Any]]:
    ssid = registry["meraki"]["primary_ssid"]
    auth_mode = ssid.get("authMode")
    if not isinstance(auth_mode, str) or not auth_mode.strip():
        raise _MissingFact(
            "Meraki SSID adapter requires native authMode, which is not declared by the template"
        )
    vlan = ssid[vlan_key]
    record = {
        "number": ssid["number"],
        "name": ssid["name"],
        "enabled": True,
        "authMode": auth_mode,
        "ipAssignmentMode": ssid["ipAssignmentMode"],
        "defaultVlanId": vlan,
        "useVlanTagging": ssid["useVlanTagging"],
    }
    return [record]


def _meraki_ssid_input(
    registry: Mapping[str, Any], scope: str, network_key: str, vlan_key: str
) -> dict[str, Any]:
    meraki = registry["meraki"]
    network_id = str(meraki[network_key])
    return _native_input(
        "adapt_meraki_ssid_snapshots",
        "meraki",
        "ssid_snapshot",
        str(meraki["organization_id"]),
        f"network:{network_id}",
        scope,
        _ssid_record(registry, vlan_key),
    )


def _meraki_audit_input(
    registry: Mapping[str, Any],
    *,
    scope: str,
    network_key: str,
    event_epoch: int,
    schedule_id: str,
) -> dict[str, Any]:
    meraki = registry["meraki"]
    network_id = str(meraki[network_key])
    # The audit is deliberately network-level context: no SSID number, actor,
    # URLs, or unrestricted before/after configuration strings are supplied.
    payload = [
        {
            "organizationId": str(meraki["organization_id"]),
            "ts": _iso(event_epoch),
            "networkId": network_id,
            "page": "Wireless > Networks",
            "label": "Updated a network setting",
        }
    ]
    return _native_input(
        "adapt_meraki_audits",
        "meraki",
        "configuration_change",
        str(meraki["organization_id"]),
        f"network:{network_id}",
        scope,
        payload,
    )


def _meraki_inventory_events(
    registry: Mapping[str, Any], event_epoch: int
) -> tuple[list[dict[str, Any]], list[str]]:
    meraki = registry["meraki"]
    devices = [
        (
            meraki["primary_network_id"],
            meraki["primary_access_point"],
            "wireless",
        ),
        (
            meraki["control_network_id"],
            meraki["control_access_point"],
            "wireless",
        ),
        (meraki["primary_network_id"], meraki["ms390"], "switch"),
    ]
    events: list[dict[str, Any]] = []
    limitations: list[str] = []
    for network_id, device, product_type in devices:
        row = {
            "name": device["name"],
            "networkId": str(network_id),
            "serial": device.get("serial", ""),
            "model": device["model"],
            "mac": device["mac"],
            "lanIp": device["lan_ip"],
            "productType": product_type,
            "organizationId": str(meraki["organization_id"]),
        }
        if not row["serial"]:
            limitations.append(
                f"Meraki inventory omitted {device['model']} device {device['name']}: the template declares no native serial strategy."
            )
            continue
        events.append(
            _envelope(
                event_epoch,
                str(device["name"]).lower(),
                "cisco_meraki_devices::networking_inventory",
                "meraki:devices",
                "cisco_meraki",
                row,
            )
        )
    if not events:
        raise _MissingFact("no Meraki inventory device has a declared native serial")
    return events, limitations


def _meraki_association(
    registry: Mapping[str, Any],
    *,
    client_key: str,
    ap_key: str,
    network_key: str,
    event_epoch: int,
) -> dict[str, Any]:
    meraki = registry["meraki"]
    client = registry[client_key]["client"]
    ap = meraki[ap_key]
    row = {
        "occurredAt": _iso(event_epoch),
        "networkId": str(meraki[network_key]),
        "type": "association",
        "clientMac": client["mac"],
        "deviceSerial": ap["serial"],
        "deviceName": ap["name"],
        "ssidNumber": meraki["primary_ssid"]["number"],
        "eventData": {"client_mac": client["mac"], "client_ip": client["ip"]},
        "organizationId": str(meraki["organization_id"]),
    }
    return _envelope(
        event_epoch,
        str(ap["name"]).lower(),
        "cisco_meraki_accesspoints::networking_wireless",
        "meraki:accesspoints",
        "cisco_meraki",
        row,
    )


def _meraki_reused_association(
    registry: Mapping[str, Any], event_epoch: int
) -> dict[str, Any]:
    meraki = registry["meraki"]
    client = _require_map(
        registry.get("client_reused"), "identity_registry.client_reused"
    ).get("client")
    client = _require_map(client, "identity_registry.client_reused.client")
    ap = meraki["primary_access_point"]
    row = {
        "occurredAt": _iso(event_epoch),
        "networkId": str(meraki["primary_network_id"]),
        "type": "association",
        "clientMac": client["mac"],
        "deviceSerial": ap["serial"],
        "deviceName": ap["name"],
        "ssidNumber": meraki["primary_ssid"]["number"],
        "eventData": {"client_mac": client["mac"], "client_ip": client["ip"]},
        "organizationId": str(meraki["organization_id"]),
    }
    return _envelope(
        event_epoch,
        str(ap["name"]).lower(),
        "cisco_meraki_accesspoints::networking_wireless",
        "meraki:accesspoints",
        "cisco_meraki",
        row,
    )


def _internal_binding_span(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    which: str,
    event_epoch: int,
    schedule_id: str,
    execution_id: str,
) -> dict[str, Any]:
    """Independent local work binds a service to a Pod; never a hero request."""
    selected = _require_map(registry.get(which), f"identity_registry.{which}")
    backend_key = "backend"
    if (
        which in {"primary", "control"}
        and scenario.get("variant_id") in {"a-backend-rollout", "b-service-backend"}
        and (
            schedule_id.endswith(
                ("-binding-change", "-binding-impact", "-binding-recovery")
            )
        )
    ):
        backend_key = "backend_v2"
    backend = _require_map(selected.get(backend_key), f"{which}.{backend_key}")
    node = _require_map(selected.get("node"), f"{which}.node")
    backend_id = _kube_ids(registry, str(backend["logical_key"]))["uid"]
    service = _require_text(
        selected.get("application_service"), f"{which}.application_service"
    )
    fields = {
        "service.name": service,
        "deployment.environment.name": "demo",
        "k8s.cluster.name": str(selected["cluster"]),
        "k8s.namespace.name": str(selected["namespace"]),
        "k8s.node.name": str(node["name"]),
        "k8s.pod.name": str(backend["name"]),
        "k8s.pod.uid": str(backend_id),
        "k8s.pod.labels.app": service,
    }
    event = {
        "trace_id": _stable_hex(
            scenario["scenario_id"],
            execution_id,
            schedule_id,
            "independent-trace",
            length=32,
        ),
        "span_id": _stable_hex(
            scenario["scenario_id"], execution_id, schedule_id, "local-work", length=16
        ),
        "parent_span_id": "",
        "name": "demo.local-work",
        "attributes": {},
        "start_time": event_epoch * 1_000_000_000,
        "end_time": event_epoch * 1_000_000_000 + 1_000_000,
        "kind": "SPAN_KIND_INTERNAL",
        "status": {"message": "", "code": "STATUS_CODE_UNSET"},
    }
    return _envelope(
        event_epoch,
        str(node["name"]),
        "kubernetes",
        "otel:traces",
        "otel_traces",
        event,
        fields,
    )


def _connected_pod_inputs_and_events(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    event_epoch: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collect the two connected workload Pods before any OTel binding."""
    primary = _require_map(registry.get("primary"), "identity_registry.primary")
    cluster = _require_text(primary.get("cluster"), "identity_registry.primary.cluster")
    namespace = _require_text(
        primary.get("namespace"), "identity_registry.primary.namespace"
    )
    scope = _require_text(
        primary.get("routing_scope"), "identity_registry.primary.routing_scope"
    )
    authority = f"cluster:{cluster}"
    pods: list[dict[str, Any]] = []
    raw_events: list[dict[str, Any]] = []
    node = _require_map(primary.get("node"), "identity_registry.primary.node")
    node_name = _require_text(node.get("name"), "identity_registry.primary.node.name")
    for which in ("inventory", "pricing"):
        selected = _require_map(registry.get(which), f"identity_registry.{which}")
        backend = _require_map(
            selected.get("backend"), f"identity_registry.{which}.backend"
        )
        logical_key = _require_text(
            backend.get("logical_key"), f"{which}.backend.logical_key"
        )
        ids = _kube_ids(registry, logical_key)
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": _require_text(backend.get("name"), f"{which}.backend.name"),
                "namespace": namespace,
                "uid": ids["uid"],
                "resourceVersion": f"rv-{_stable_hex(scenario['scenario_id'], logical_key, 'pod-rv', length=12)}",
                "labels": {
                    "app.kubernetes.io/name": str(selected["application_service"])
                },
            },
            "spec": {"nodeName": node_name},
            "status": {
                "phase": "Running",
                "hostIP": node["ip"],
                "podIP": backend["ip"],
                "podIPs": [{"ip": backend["ip"]}],
            },
        }
        pods.append(pod)
        raw_events.append(
            _kube_watch_event(event_epoch, cluster, namespace, node_name, "pods", pod)
        )
    list_version = f"rv-{_stable_hex(scenario['scenario_id'], cluster, namespace, 'connected-pod-list-rv', length=12)}"
    native_inputs = [
        _native_input(
            "adapt_pods",
            "kubernetes",
            "pod_snapshot",
            authority,
            f"namespace:{namespace}",
            scope,
            {
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": {"resourceVersion": list_version},
                "items": [pod],
            },
        )
        for pod in pods
    ]
    return native_inputs, raw_events


def _connected_hubble_event(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    schedule_id: str,
    event_epoch: int,
) -> dict[str, Any]:
    """Emit one native Pod-to-Pod baseline flow for each connected service."""
    primary = _require_map(registry.get("primary"), "identity_registry.primary")
    target = "inventory" if "inventory" in schedule_id else "pricing"
    selected = _require_map(registry.get(target), f"identity_registry.{target}")
    client = _require_map(primary.get("backend"), "identity_registry.primary.backend")
    backend = _require_map(
        selected.get("backend"), f"identity_registry.{target}.backend"
    )
    node = _require_map(primary.get("node"), "identity_registry.primary.node")
    cluster = _require_text(primary.get("cluster"), "identity_registry.primary.cluster")
    namespace = _require_text(
        primary.get("namespace"), "identity_registry.primary.namespace"
    )
    client_ids = _kube_ids(registry, str(client["logical_key"]))
    backend_ids = _kube_ids(registry, str(backend["logical_key"]))
    source_labels = {"app.kubernetes.io/name": str(primary["application_service"])}
    destination_labels = {
        "app.kubernetes.io/name": str(selected["application_service"])
    }
    source = _hubble_endpoint(
        cluster, namespace, str(client["name"]), client_ids["uid"], source_labels
    )
    destination = _hubble_endpoint(
        cluster, namespace, str(backend["name"]), backend_ids["uid"], destination_labels
    )
    flow_port = 41000 + _stable_int(
        scenario["scenario_id"], schedule_id, "source-port", modulus=2000
    )
    flow = {
        "time": _iso(event_epoch, "proto"),
        "uuid": str(uuid.uuid5(NS, f"{scenario['scenario_id']}:{schedule_id}:hubble")),
        "verdict": "FORWARDED",
        "IP": {
            "source": str(client["ip"]),
            "destination": str(backend["ip"]),
            "ipVersion": "IPv4",
        },
        "l4": {
            "TCP": {
                "source_port": flow_port,
                "destination_port": int(backend["port"]),
                "flags": {"SYN": True},
            }
        },
        "source": source,
        "destination": destination,
        "Type": "L3_L4",
        "node_name": f"{cluster}/{node['name']}",
        "event_type": {"type": 4, "sub_type": 0},
        "traffic_direction": "EGRESS",
        "trace_observation_point": "TO_ENDPOINT",
        "trace_reason": "NEW",
        "is_reply": False,
        "Summary": "TCP Flags: SYN",
    }
    row = {"flow": flow, "node_name": f"{cluster}/{node['name']}", "time": flow["time"]}
    return _envelope(
        event_epoch,
        str(node["name"]),
        HUBBLE_FILE,
        "cilium:hubble:flow",
        "cilium_hubble",
        row,
        {
            "k8s.node.name": str(node["name"]),
            "k8s.cluster.name": cluster,
            "log.file.path": HUBBLE_FILE,
        },
    )


def _kube_ids(registry: Mapping[str, Any], logical_key: str) -> Mapping[str, str]:
    try:
        return registry["materialized_kubernetes_ids"][logical_key]
    except (KeyError, TypeError) as exc:
        raise _MissingFact(
            f"identity_registry lacks declared Kubernetes IDs for {logical_key}"
        ) from exc


def _kube_objects(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    which: str,
    *,
    backend_key: str = "backend",
) -> tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    roots = _require_map(scenario.get("identity_registry"), "identity_registry")
    selected = roots.get("control") if which == "control" else roots.get("primary")
    if not isinstance(selected, Mapping):
        raise _MissingFact(
            f"identity_registry.{which} is required for Kubernetes prelude"
        )
    cluster = _require_text(
        selected.get("cluster"), f"identity_registry.{which}.cluster"
    )
    namespace = _require_text(
        selected.get("namespace"), f"identity_registry.{which}.namespace"
    )
    scope = _require_text(
        selected.get("routing_scope"), f"identity_registry.{which}.routing_scope"
    )
    authority = f"cluster:{cluster}"
    service = _require_map(
        selected.get("frontend"), f"identity_registry.{which}.frontend"
    )
    backend = _require_map(
        selected.get(backend_key), f"identity_registry.{which}.{backend_key}"
    )
    node = _require_map(selected.get("node"), f"identity_registry.{which}.node")
    service_key = _require_text(service.get("logical_key"), "frontend.logical_key")
    backend_key = _require_text(backend.get("logical_key"), "backend.logical_key")
    node_key = _require_text(node.get("logical_key"), "node.logical_key")
    service_ids = _kube_ids(registry, service_key)
    backend_ids = _kube_ids(registry, backend_key)
    node_ids = _kube_ids(registry, node_key)
    service_name = _require_text(service.get("name"), "frontend.name")
    backend_name = _require_text(backend.get("name"), "backend.name")
    node_name = _require_text(node.get("name"), "node.name")
    app_service = _require_text(
        selected.get("application_service"), "application_service"
    )
    backend_label = {"app.kubernetes.io/name": app_service}
    service_obj = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": service_name,
            "namespace": namespace,
            "uid": service_ids["uid"],
            "resourceVersion": f"rv-{_stable_hex(scenario['scenario_id'], service_key, 'service-rv', length=12)}",
            "generation": 1,
            "labels": {"app.kubernetes.io/name": app_service},
        },
        "spec": {
            "type": "LoadBalancer",
            "clusterIP": "10.96.0.20" if which != "control" else "10.96.0.30",
            "externalTrafficPolicy": "Local",
            "internalTrafficPolicy": "Cluster",
            "selector": backend_label,
            "ports": [
                {
                    "name": "http",
                    "protocol": str(service.get("protocol", "TCP")),
                    "port": int(service.get("port", 8080)),
                    "targetPort": int(service.get("port", 8080)),
                }
            ],
        },
        "status": {"loadBalancer": {"ingress": [{"ip": service["ip"]}]}},
    }
    pod_obj = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": backend_name,
            "namespace": namespace,
            "uid": backend_ids["uid"],
            "resourceVersion": f"rv-{_stable_hex(scenario['scenario_id'], backend_key, 'pod-rv', length=12)}",
            "generation": 1,
            "labels": {
                **backend_label,
                "app.kubernetes.io/version": "1.0.0",
                "pod-template-hash": backend_ids["pod_template_hash"],
            },
            "ownerReferences": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": f"{backend_name}-{backend_ids['pod_template_hash']}",
                    "uid": backend_ids["replica_set_uid"],
                    "controller": True,
                }
            ],
        },
        "spec": {"nodeName": node_name},
        "status": {
            "phase": "Running",
            "hostIP": node["ip"],
            "hostIPs": [{"ip": node["ip"]}],
            "podIP": backend["ip"],
            "podIPs": [{"ip": backend["ip"]}],
        },
    }
    # EndpointSlice identity belongs to the stable Service. A rollout changes
    # its resourceVersion and target Pod UID, not the slice's native UID.
    endpoint_slice_ids = _kube_ids(registry, service_key)
    endpoint_slice = {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": f"{service_name}-slice",
            "namespace": namespace,
            "uid": endpoint_slice_ids["endpointslice_uid"],
            "resourceVersion": f"rv-{_stable_hex(scenario['scenario_id'], backend_key, 'slice-rv', length=12)}",
            "labels": {"kubernetes.io/service-name": service_name},
        },
        "addressType": "IPv4",
        "ports": [
            {
                "name": "http",
                "protocol": str(service.get("protocol", "TCP")),
                "port": int(service.get("port", 8080)),
            }
        ],
        "endpoints": [
            {
                "addresses": [backend["ip"]],
                "nodeName": node_name,
                "conditions": {"ready": True},
                "targetRef": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "name": backend_name,
                    "namespace": namespace,
                    "uid": backend_ids["uid"],
                },
            }
        ],
    }
    node_obj = {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {
            "name": node_name,
            "uid": node_ids["uid"],
            "resourceVersion": f"rv-{_stable_hex(scenario['scenario_id'], node_key, 'node-rv', length=12)}",
        },
        "status": {
            "addresses": [
                {"type": "InternalIP", "address": node["ip"]},
                {"type": "Hostname", "address": node_name},
            ]
        },
    }
    list_version = f"rv-{_stable_hex(scenario['scenario_id'], cluster, namespace, 'list-rv', length=12)}"
    service_list = {
        "apiVersion": "v1",
        "kind": "ServiceList",
        "metadata": {"resourceVersion": list_version},
        "items": [service_obj],
    }
    endpoint_list = {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSliceList",
        "metadata": {"resourceVersion": list_version},
        "items": [endpoint_slice],
    }
    pod_list = {
        "apiVersion": "v1",
        "kind": "PodList",
        "metadata": {"resourceVersion": list_version},
        "items": [pod_obj],
    }
    context = {
        "cluster": cluster,
        "authority": authority,
        "scope": scope,
        "namespace": namespace,
        "node_name": node_name,
    }
    objects = {
        "service": service_obj,
        "pod": pod_obj,
        "endpoint_slice": endpoint_slice,
        "node": node_obj,
    }
    return (
        cluster,
        namespace,
        context,
        service_list,
        endpoint_list,
        pod_list | {"_objects": objects},
    )


def _kube_watch_event(
    event_epoch: int,
    cluster: str,
    namespace: str | None,
    node_name: str,
    resource: str,
    object_value: Mapping[str, Any],
    *,
    event_type: str = "ADDED",
) -> dict[str, Any]:
    object_name = str(object_value.get("metadata", {}).get("name", resource))
    fields: dict[str, str] = {
        "metric_source": "kubernetes",
        "k8s.cluster.name": cluster,
        "k8s.resource.name": resource,
        "event.domain": "k8s",
        "event.name": object_name,
    }
    if namespace is not None:
        fields["k8s.namespace.name"] = namespace
    if object_value.get("kind") == "Pod":
        fields["k8s.node.name"] = node_name
    return _envelope(
        event_epoch,
        node_name,
        "kubernetes",
        f"kube:object:{resource}",
        "k8s",
        {"type": event_type, "object": dict(object_value)},
        fields,
    )


def _kubernetes_inputs_and_events(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    which: str,
    event_epoch: int,
    *,
    backend_key: str = "backend",
    update_watch: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cluster, namespace, context, services, slices, pods_with_objects = _kube_objects(
        scenario, registry, which, backend_key=backend_key
    )
    objects = pods_with_objects.pop("_objects")
    scope = str(context["scope"])
    authority = str(context["authority"])
    common = {
        "authority": authority,
        "partition": f"namespace:{namespace}",
        "scope": scope,
    }
    if update_watch:
        # The Service remains unchanged but its watch resourceVersion advances.
        # The new Pod is a new native UID and the existing EndpointSlice is
        # modified to target that UID. This is local synthetic watch evidence,
        # not a Service configuration change or deployment claim.
        objects["service"]["metadata"]["resourceVersion"] = "rv-" + _stable_hex(
            scenario["scenario_id"],
            objects["service"]["metadata"]["uid"],
            event_epoch,
            "service-rollout-watch-rv",
            length=12,
        )
    native_inputs = [
        _native_input(
            "adapt_services",
            "kubernetes",
            "service_snapshot",
            common["authority"],
            common["partition"],
            scope,
            services,
        ),
        _native_input(
            "adapt_endpointslices",
            "kubernetes",
            "endpointslice_snapshot",
            common["authority"],
            common["partition"],
            scope,
            slices,
        ),
        _native_input(
            "adapt_pods",
            "kubernetes",
            "pod_snapshot",
            common["authority"],
            common["partition"],
            scope,
            pods_with_objects,
        ),
    ]
    node_name = str(context["node_name"])
    raw_events = [
        _kube_watch_event(
            event_epoch,
            cluster,
            namespace,
            node_name,
            "services",
            objects["service"],
            event_type="MODIFIED" if update_watch else "ADDED",
        ),
        _kube_watch_event(
            event_epoch, cluster, namespace, node_name, "pods", objects["pod"]
        ),
        _kube_watch_event(
            event_epoch,
            cluster,
            namespace,
            node_name,
            "endpointslices",
            objects["endpoint_slice"],
            event_type="MODIFIED" if update_watch else "ADDED",
        ),
        _kube_watch_event(
            event_epoch, cluster, None, node_name, "nodes", objects["node"]
        ),
    ]
    if update_watch:
        raw_events[0] = _kube_watch_event(
            event_epoch,
            cluster,
            namespace,
            node_name,
            "services",
            objects["service"],
            event_type="MODIFIED",
        )
        raw_events = [
            event
            for event in raw_events
            if event.get("fields", {}).get("k8s.resource.name")
            in {"services", "pods", "endpointslices"}
        ]
    return native_inputs, raw_events


def _profile_for_exporter(registry: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    for item in registry.get("stream_exporters", []):
        if item.get("logical_key") == key:
            return item
    raise _MissingFact(f"identity_registry.stream_exporters lacks {key}")


def _stream_tuple(
    scenario: Mapping[str, Any], schedule_id: str
) -> tuple[Mapping[str, Any], Mapping[str, Any], int, int]:
    roots = _require_map(scenario.get("identity_registry"), "identity_registry")
    if schedule_id.startswith("a-"):
        which = "control" if "control" in schedule_id else "primary"
        spec = _require_map(roots.get(which), f"identity_registry.{which}")
        client = _require_map(spec.get("client"), f"identity_registry.{which}.client")
        frontend = _require_map(
            spec.get("frontend"), f"identity_registry.{which}.frontend"
        )
        if "control" in schedule_id:
            port = 55230
        elif "recovery" in schedule_id:
            port = 55222
        elif "impact" in schedule_id:
            port = 55221
        else:
            port = 55220
        return client, frontend, port, 8080
    spec = _require_map(roots.get("primary"), "identity_registry.primary")
    client = _require_map(spec.get("client"), "identity_registry.primary.client")
    frontend = _require_map(spec.get("frontend"), "identity_registry.primary.frontend")
    port = (
        54120
        if "baseline" in schedule_id
        else 54122
        if "recovery" in schedule_id
        else 54121
    )
    # A direct helper value is returned in place of the exporter; the caller
    # selects the exact row from the schedule ID (campus or SD-WAN).
    return client, frontend, port, 8080


def _stream_event(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    schedule_id: str,
    event_epoch: int,
) -> dict[str, Any]:
    client, frontend, source_port, destination_port = _stream_tuple(
        scenario, schedule_id
    )
    if scenario["scenario_id"] == "track-a-firewall":
        exporter_key = (
            "exporter.control_ms390"
            if "control" in schedule_id
            else "exporter.primary_ms390"
        )
    else:
        exporter_key = (
            "exporter.sdwan"
            if schedule_id.endswith("connection")
            else "exporter.campus_fnf"
        )
    exporter = _profile_for_exporter(registry, exporter_key)
    source_ip, dest_ip = str(client["ip"]), str(frontend["ip"])
    if (
        scenario.get("variant_id") == "a-nat-boundary"
        and schedule_id == "a-nat-downstream-flow"
    ):
        nat = _require_map(
            scenario.get("identity_registry", {}).get("nat_boundary"),
            "identity_registry.nat_boundary",
        )
        source_ip = str(nat["translated_initiator_ip"])
        dest_ip = str(nat["downstream_destination_ip"])
        source_port = int(nat["translated_initiator_port"])
        destination_port = int(nat["downstream_destination_port"])
    observation_domain_id = int(exporter["observation_domain_id"])
    flow: dict[str, Any] = {
        "timestamp": _iso(event_epoch, "us"),
        "endtime": _iso(event_epoch, "us"),
        "netflow_version": 10,
        "seqnumber": _stable_int(
            scenario["scenario_id"], schedule_id, "seq", modulus=2**31 - 1
        ),
        "exporter_ip": str(exporter["address"]),
        "exporter_sampling_interval": 1,
        "observation_domain_id": observation_domain_id,
        "src_ip": source_ip,
        "dest_ip": dest_ip,
        "src_port": source_port,
        "dest_port": destination_port,
        "protoid": 6,
        "tos": 0,
        "bytes": 1280,
        "packets": 4,
        "tcp_flags": 27,
        "version": 4,
    }
    if exporter.get("vpn_id"):
        flow["vpn_id"] = str(exporter["vpn_id"])
    return _envelope(
        event_epoch,
        STREAM_FORWARDER,
        "stream:netflow",
        "stream:netflow",
        "netflow",
        flow,
    )


def _nd_flow_event(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    schedule_id: str,
    event_epoch: int,
) -> dict[str, Any]:
    """Emit the documented Nexus Dashboard flow shape for the exact frontend tuple."""
    nd = _require_map(registry.get("nd"), "identity_registry.nd")
    selected = _require_map(registry.get("primary"), "identity_registry.primary")
    client = _require_map(selected.get("client"), "identity_registry.primary.client")
    frontend = _require_map(
        selected.get("frontend"), "identity_registry.primary.frontend"
    )
    ordinal = (
        "baseline"
        if "baseline" in schedule_id
        else "recovery"
        if "recovery" in schedule_id
        else "impact"
    )
    source_port = {"baseline": 54120, "impact": 54121, "recovery": 54122}[ordinal]
    stats = {
        "nodeNames": [str(nd["leaf"])],
        "ingressVif": ["eth1/24"],
        "egressVif": ["eth1/49"],
        "ingressByteCount": 1280,
        "egressByteCount": 1280,
        "ingressPktCount": 1,
        "egressPktCount": 1,
        "dropPktCount": 0,
        "dropReasons": [],
    }
    payload = {
        "flowId": str(uuid.uuid5(NS, f"{scenario['scenario_id']}:{schedule_id}:nd")),
        "ts": _iso(event_epoch, "ms"),
        "srcIp": str(client["ip"]),
        "dstIp": str(frontend["ip"]),
        "srcPort": source_port,
        "dstPort": int(frontend["port"]),
        "protocolName": "TCP",
        "stats": [stats],
        "nd_host": str(nd["authority"]),
        "fabricName": str(nd["fabric"]),
    }
    return _envelope(
        ((event_epoch // 300) + 1) * 300,
        HEAVY_FORWARDER,
        "flows",
        "cisco:dc:nd:flows",
        "cisco_dc",
        payload,
    )


def _hubble_endpoint(
    cluster: str, namespace: str, pod_name: str, uid: str, labels: Mapping[str, str]
) -> dict[str, Any]:
    endpoint_labels = [f"k8s:{key}={value}" for key, value in sorted(labels.items())]
    endpoint_labels.extend(
        [
            f"k8s:io.kubernetes.pod.namespace={namespace}",
            f"k8s:io.cilium.k8s.policy.cluster={cluster}",
            "k8s:io.cilium.k8s.policy.serviceaccount=default",
        ]
    )
    endpoint_labels.sort()
    identity = 10_000 + _stable_int(cluster, uid, "hubble-identity", modulus=900_000)
    return {
        "ID": _stable_int(cluster, uid, "hubble-endpoint-id", modulus=2**31 - 1),
        "identity": identity,
        "cluster_name": cluster,
        "namespace": namespace,
        "labels": endpoint_labels,
        "pod_name": pod_name,
        "workloads": [{"name": pod_name.rsplit("-", 1)[0], "kind": "Deployment"}],
    }


def _hubble_event(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    schedule_id: str,
    event_epoch: int,
) -> dict[str, Any]:
    roots = _require_map(scenario.get("identity_registry"), "identity_registry")
    if scenario["scenario_id"] == "track-a-firewall":
        which = "control" if "control" in schedule_id else "primary"
    else:
        which = "primary"
    selected = _require_map(roots.get(which), f"identity_registry.{which}")
    client = _require_map(selected.get("client"), f"identity_registry.{which}.client")
    service = _require_map(
        selected.get("frontend"), f"identity_registry.{which}.frontend"
    )
    backend = _require_map(
        selected.get("backend"), f"identity_registry.{which}.backend"
    )
    node = _require_map(selected.get("node"), f"identity_registry.{which}.node")
    cluster = str(selected["cluster"])
    namespace = str(selected["namespace"])
    service_name = str(selected.get("application_service", service["name"]))
    flow_port = (
        55230
        if "control" in schedule_id
        else 55222
        if "recovery" in schedule_id
        else 55221
        if "impact" in schedule_id
        else 55220
    )
    if scenario["scenario_id"] == "track-b-fabric":
        flow_port = (
            54120
            if "baseline" in schedule_id
            else 54122
            if "recovery" in schedule_id
            else 54121
        )
    source_ip = str(client["ip"])
    if (
        scenario.get("variant_id") == "a-nat-boundary"
        and "nat-downstream" in schedule_id
    ):
        source_ip = str(registry["nat_boundary"]["translated_initiator_ip"])
    backend = selected.get("backend")
    if scenario.get("variant_id") in {"a-backend-rollout", "b-service-backend"} and any(
        token in schedule_id for token in ("change", "impact", "recovery")
    ):
        backend = selected.get("backend_v2")
    backend = _require_map(backend, f"{which}.backend")
    # Resolve the identity only after selecting the source-backed backend for
    # this scheduled flow. Rollout variants deliberately use a different Pod
    # UID; carrying the default UID beside the new Pod name/IP would fabricate
    # an internally inconsistent Hubble endpoint.
    backend_ids = _kube_ids(registry, str(backend["logical_key"]))
    backend_ip = str(backend["ip"])
    flow_time = _iso(event_epoch, "proto")
    flow_id = str(uuid.uuid5(NS, f"{scenario['scenario_id']}:{schedule_id}:hubble"))
    pod_labels = {
        "app.kubernetes.io/name": service_name,
        "app.kubernetes.io/version": "1.0.0",
    }
    flow = {
        "time": flow_time,
        "uuid": flow_id,
        "verdict": "FORWARDED",
        "IP": {"source": source_ip, "destination": backend_ip, "ipVersion": "IPv4"},
        "l4": {
            "TCP": {
                "source_port": flow_port,
                "destination_port": int(backend.get("port", 8080)),
                "flags": {"SYN": True},
            }
        },
        "source": {"identity": 2, "labels": ["reserved:world"]},
        "destination": _hubble_endpoint(
            cluster, namespace, str(backend["name"]), backend_ids["uid"], pod_labels
        ),
        "Type": "L3_L4",
        "node_name": f"{cluster}/{node['name']}",
        "event_type": {"type": 4, "sub_type": 0},
        "traffic_direction": "INGRESS",
        "trace_observation_point": "TO_ENDPOINT",
        "trace_reason": "NEW",
        "is_reply": False,
        "Summary": "TCP Flags: SYN",
    }
    row = {"flow": flow, "node_name": f"{cluster}/{node['name']}", "time": flow_time}
    return _envelope(
        event_epoch,
        str(node["name"]),
        HUBBLE_FILE,
        "cilium:hubble:flow",
        "cilium_hubble",
        row,
        {
            "k8s.node.name": str(node["name"]),
            "k8s.cluster.name": cluster,
            "log.file.path": HUBBLE_FILE,
        },
    )


def _ftd_event(
    scenario: Mapping[str, Any], schedule_id: str, event_epoch: int
) -> dict[str, Any]:
    if scenario["scenario_id"] != "track-a-firewall":
        raise _MissingFact("FTD is not a source in Track B")
    roots = _require_map(scenario.get("identity_registry"), "identity_registry")
    firewall_key = (
        "control_firewall" if schedule_id == "a-control-connection" else "firewall"
    )
    firewall = _require_map(
        roots.get(firewall_key), f"identity_registry.{firewall_key}"
    )
    if firewall.get("authority") != firewall.get("source_host"):
        raise _MissingFact("FTD authority must exactly equal bare SourceHost")
    expected_device_ip = (
        "10.71.255.11" if firewall_key == "control_firewall" else "10.71.255.10"
    )
    if str(firewall.get("device_ip")) != expected_device_ip:
        raise _MissingFact(
            f"{firewall_key} FTD DeviceIP must remain {expected_device_ip}"
        )
    selected = (
        roots["control"] if schedule_id == "a-control-connection" else roots["primary"]
    )
    client = selected["client"]
    frontend = selected["frontend"]
    source_port = (
        55230
        if schedule_id == "a-control-connection"
        else 55221
        if "impact" in schedule_id
        else 55222
        if "recovery" in schedule_id
        else 55220
    )
    rollout_allow = scenario.get(
        "variant_id"
    ) == "a-backend-rollout" and schedule_id in {
        "a-rollout-baseline-connection",
        "a-rollout-impact-connection",
        "a-rollout-recovery-connection",
    }
    action = (
        "Allow" if rollout_allow else "Block" if "impact" in schedule_id else "Allow"
    )
    counter = 100 + _stable_int(
        scenario["scenario_id"], schedule_id, "connection", modulus=99_000
    )
    native = {
        "EventType": "ConnectionEvent",
        "FirstPacketSecond": event_epoch,
        "DeviceIP": str(firewall["device_ip"]),
        "ConnectionID": counter,
        "InstanceID": 1,
        "InitiatorIP": str(client["ip"]),
        "InitiatorPort": source_port,
        "ResponderIP": str(frontend["ip"]),
        "ResponderPort": int(frontend["port"]),
        "Protocol": "TCP",
        "InitiatorBytes": 1280,
        "ResponderBytes": 0 if action == "Block" else 640,
        "InitiatorPackets": 2,
        "ResponderPackets": 0 if action == "Block" else 1,
        "AC_RuleAction": action,
        "SourceHost": str(firewall["source_host"]),
    }
    if (
        scenario.get("variant_id") == "a-nat-boundary"
        and schedule_id == "a-nat-source-observation"
    ):
        nat = _require_map(
            scenario.get("identity_registry", {}).get("nat_boundary"), "nat_boundary"
        )
        native.update(
            {
                "NAT_InitiatorIP": str(nat["translated_initiator_ip"]),
                "NAT_InitiatorPort": int(nat["translated_initiator_port"]),
                "NAT_ResponderIP": str(nat["downstream_destination_ip"]),
                "NAT_ResponderPort": int(nat["downstream_destination_port"]),
            }
        )
    return _envelope(
        event_epoch,
        str(firewall["source_host"]),
        f"sbg_fw_estreamer_input://{firewall['device_alias']}",
        "cisco:sfw:estreamer",
        "cisco_secure_fw",
        json.dumps(native, ensure_ascii=False),
    )


def _catalyst_client_event(
    scenario: Mapping[str, Any], registry: Mapping[str, Any], event_epoch: int
) -> dict[str, Any]:
    roots = _require_map(scenario.get("identity_registry"), "identity_registry")
    client = _require_map(roots.get("primary"), "identity_registry.primary")["client"]
    catalyst = registry["catalyst"]
    client_spec = scenario["identity_registry"]["primary"]["client"]
    if client_spec.get("logical_key") != "client.primary":
        raise _MissingFact(
            "Catalyst client snapshot must use the declared primary client"
        )
    device_mac = str(catalyst["device_mac"]).lower()
    native = {
        "macAddress": str(client["mac"]),
        "ipv4Address": str(client["ip"]),
        "type": "Wired",
        "connectionStatus": "connected",
        "lastUpdatedTime": event_epoch * 1000,
        "connectedNetworkDevice": {
            "connectedNetworkDeviceName": str(catalyst["device_alias"]),
            "connectedNetworkDeviceManagementIp": str(catalyst["device_management_ip"]),
            "connectedNetworkDeviceMac": device_mac,
            "connectedNetworkDeviceType": "Switch",
            "interfaceName": str(catalyst["interface"]),
        },
        "cisco_catalyst_host": str(catalyst["authority"]),
    }
    # The logical alias is not a native client ID.  The normalized contract
    # falls back to the source-provided MAC when `id` is absent.
    return _envelope(
        event_epoch,
        str(catalyst["device_alias"]).lower(),
        "cisco_catalyst_dnac_client://campus_wired",
        "cisco:dnac:client",
        "cisco_catalyst",
        native,
    )


def _aci_kv(key: str, value: Any) -> str:
    text = str(value)
    if text.replace(".", "").isdigit():
        return f"{key}={text}"
    if text == "":
        return f'{key}=""'
    return f'{key}="{text}"'


def _aci_raw(
    event_epoch: int, attrs: Sequence[tuple[str, Any]], apic_host: str, component: str
) -> str:
    at = _utc(event_epoch).strftime("%Y-%m-%d %H:%M:%S")
    pairs = [at, *(_aci_kv(key, value) for key, value in attrs)]
    pairs.extend(
        [
            _aci_kv("apic_host", apic_host),
            _aci_kv("actual_host", apic_host),
            _aci_kv("component", component),
        ]
    )
    return "\t".join(pairs)


def _aci_endpoint_events(
    registry: Mapping[str, Any], event_epoch: int
) -> list[dict[str, Any]]:
    aci = registry["aci"]
    apic_authority = str(aci["authority"])
    apic_host = apic_authority.removeprefix("https://").split("/", 1)[0]
    pod = registry["primary"]["backend"]
    database = registry["primary"]["database"]
    endpoints = [
        (
            pod,
            str(aci["source_endpoint_mac"]),
            str(aci["consumer_epg_dn"]),
            str(aci["consumer_encap"]),
        ),
        (
            database,
            str(aci["database_endpoint_mac"]),
            str(aci["provider_epg_dn"]),
            str(aci["provider_encap"]),
        ),
    ]
    path = f"topology/pod-{aci['pod_id']}/paths-{aci['leaf_node_id']}/pathep-[{aci['leaf_interface']}]"
    raw_events: list[dict[str, Any]] = []
    for obj, mac, epg_dn, encap in endpoints:
        ip = str(obj["ip"])
        cep_dn = f"{epg_dn}/cep-{mac}"
        common_attrs = [
            ("dn", cep_dn),
            ("encap", encap),
            ("id", "0"),
            ("ip", ip),
            ("lcC", "learned"),
            ("lcOwn", "local"),
            ("mac", mac),
            ("name", mac),
            ("status", ""),
            ("uid", "0"),
        ]
        raw_events.append(
            _envelope(
                event_epoch,
                HEAVY_FORWARDER,
                "cisco_nexus_aci://classInfo_faultInst",
                "cisco:dc:aci:class",
                "cisco_dc",
                _aci_raw(
                    event_epoch, common_attrs + [("addr", ip)], apic_host, "fvCEp"
                ),
            )
        )
        stats_attrs = common_attrs + [
            ("forceResolve", "yes"),
            ("lcC", "learned"),
            ("rType", "mo"),
            ("rn", f"rscEpToPathEp-[{path}]"),
            ("state", "formed"),
            ("stateQual", "none"),
            ("tCl", "fabricPathEp"),
            ("tDn", path),
            ("tType", "mo"),
            ("addr", ip),
        ]
        raw_events.append(
            _envelope(
                event_epoch,
                HEAVY_FORWARDER,
                "cisco_nexus_aci://stats",
                "cisco:dc:aci:stats",
                "cisco_dc",
                _aci_raw(event_epoch, stats_attrs, apic_host, "fvCEp"),
            )
        )
    return raw_events


def _aci_endpoint_snapshot(
    scenario: Mapping[str, Any],
    registry: Mapping[str, Any],
    event_epoch: int,
    *,
    updated: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return one native fvCEp response and its independently indexed TA row."""
    aci = _require_map(
        scenario.get("identity_registry", {}).get("aci"),
        "identity_registry.aci",
    )
    endpoint = _require_map(
        aci.get("attachment_endpoint"), "identity_registry.aci.attachment_endpoint"
    )
    authority = _require_text(aci.get("authority"), "identity_registry.aci.authority")
    apic_host = authority.removeprefix("https://").split("/", 1)[0]
    endpoint_dn = _require_text(endpoint.get("dn"), "attachment_endpoint.dn")
    fabric_path_key = "fabric_path_dn_updated" if updated else "fabric_path_dn"
    fabric_path_dn = _require_text(endpoint.get(fabric_path_key), fabric_path_key)
    encapsulation = _require_text(endpoint.get("encap"), "attachment_endpoint.encap")
    learning = _require_text(
        endpoint.get("learning_classification"),
        "attachment_endpoint.learning_classification",
    )
    ownership = _require_text(
        endpoint.get("ownership"), "attachment_endpoint.ownership"
    )
    flattened = {
        "component": "fvCEp",
        "apic_host": apic_host,
        "dn": endpoint_dn,
        "fabricPathDn": fabric_path_dn,
        "encap": encapsulation,
        "lcC": learning,
        "lcOwn": ownership,
    }
    native = _native_input(
        "adapt_aci_endpoint_state_snapshots",
        "aci",
        "endpoint_state_snapshot",
        authority,
        f"fabric:{aci['fabric']}",
        "change-b",
        [flattened],
    )
    raw = aci_endpoint_snapshot_event(
        event_host=HEAVY_FORWARDER,
        emitted_at=_utc(event_epoch),
        apic_host=apic_host,
        endpoint_dn=endpoint_dn,
        fabric_path_dn=fabric_path_dn,
        encapsulation=encapsulation,
        learning_classification=learning,
        ownership=ownership,
    )
    return native, raw


def _aci_policy_inputs(
    registry: Mapping[str, Any],
    *,
    scope: str,
    narrowed: bool,
) -> list[dict[str, Any]]:
    aci = registry["aci"]
    authority = str(aci["authority"])
    partition = f"fabric:{aci['fabric']}"
    max_port = str(
        aci["filter_to_port_impact"] if narrowed else aci["filter_to_port_baseline"]
    )
    filter_snapshot = [
        {
            "vzFilter": {
                "attributes": {"dn": aci["filter_dn"], "name": "checkout-db"},
                "children": [
                    {
                        "vzEntry": {
                            "attributes": {
                                "dn": aci["filter_entry_dn"],
                                "name": "database-5432",
                                "etherT": "ipv4",
                                "prot": "tcp",
                                "dFromPort": str(aci["filter_from_port_baseline"]),
                                "dToPort": max_port,
                                "sFromPort": "unspecified",
                                "sToPort": "unspecified",
                            }
                        }
                    }
                ],
            }
        }
    ]
    relation_snapshot = [
        {
            "vzBrCP": {
                "attributes": {"dn": aci["contract_dn"], "name": "checkout-db"},
                "children": [
                    {
                        "vzSubj": {
                            "attributes": {
                                "dn": aci["subject_dn"],
                                "name": "checkout-db",
                                "revFltPorts": "true",
                                "provmatchT": "All",
                            },
                            "children": [
                                {
                                    "vzRsSubjFiltAtt": {
                                        "attributes": {
                                            "dn": f"{aci['subject_dn']}/rssubjFiltAtt-checkout-db",
                                            "tnVzFilterName": "checkout-db",
                                            "tDn": aci["filter_dn"],
                                        }
                                    }
                                }
                            ],
                        }
                    }
                ],
            }
        }
    ]
    attachment_snapshot = [
        {
            "fvAEPg": {
                "attributes": {"dn": aci["consumer_epg_dn"], "name": "checkout"},
                "children": [
                    {
                        "fvRsCons": {
                            "attributes": {
                                "dn": f"{aci['consumer_epg_dn']}/rscons-checkout-db",
                                "tnVzBrCPName": "checkout-db",
                                "tDn": aci["contract_dn"],
                            }
                        }
                    }
                ],
            }
        },
        {
            "fvAEPg": {
                "attributes": {"dn": aci["provider_epg_dn"], "name": "orders-db"},
                "children": [
                    {
                        "fvRsProv": {
                            "attributes": {
                                "dn": f"{aci['provider_epg_dn']}/rsprov-checkout-db",
                                "tnVzBrCPName": "checkout-db",
                                "tDn": aci["contract_dn"],
                            }
                        }
                    }
                ],
            }
        },
    ]
    return [
        _native_input(
            "adapt_aci_policy_snapshots",
            "aci",
            "filter_entry_snapshot",
            authority,
            partition,
            scope,
            filter_snapshot,
        ),
        _native_input(
            "adapt_aci_policy_snapshots",
            "aci",
            "contract_subject_snapshot",
            authority,
            partition,
            scope,
            relation_snapshot,
        ),
        _native_input(
            "adapt_aci_policy_snapshots",
            "aci",
            "epg_contract_attachment_snapshot",
            authority,
            partition,
            scope,
            attachment_snapshot,
        ),
    ]


def _aci_audit_input(
    registry: Mapping[str, Any], schedule_id: str, event_epoch: int
) -> dict[str, Any]:
    aci = registry["aci"]
    attributes = {
        "id": str(
            100_000_000 + _stable_int(schedule_id, "aci-audit-id", modulus=900_000_000)
        ),
        "affected": str(aci["filter_entry_dn"]),
        "code": "E4205000",
        "created": _iso(event_epoch, "offset_ms"),
        "ind": "modification",
        "trig": "config",
        "txId": str(
            100_000_000 + _stable_int(schedule_id, "aci-tx-id", modulus=900_000_000)
        ),
        "user": str(aci["audit_user"]),
    }
    native = [{"aaaModLR": {"attributes": attributes}}]
    return _native_input(
        "adapt_aci_audits",
        "aci",
        "aaa_mod_lr",
        str(aci["authority"]),
        f"fabric:{aci['fabric']}",
        "change-b",
        native,
    )


def _sdwan_audit_input(registry: Mapping[str, Any], event_epoch: int) -> dict[str, Any]:
    sdwan = registry["sdwan"]
    native = [
        {
            "auditdetails": [],
            "entry_time": event_epoch * 1000,
            # The reviewed schema requires this text field. Empty means the
            # source record does not give us a usable target binding.
            "logdeviceid": "",
            "logfeature": "user",
            "logid": str(uuid.uuid5(NS, "track-b-fabric:b-unrelated-wan-change:logid")),
            "logmessage": "Audit log entry.",
            "logmodule": "user",
            "loguser": str(uuid.uuid5(NS, "track-b-fabric:sdwan:audit-actor")),
            "logusersrcip": "",
            "statcycletime": event_epoch * 1000,
            "tenant": "default",
        }
    ]
    return _native_input(
        "adapt_sdwan_audits",
        "sdwan",
        "audit_log",
        str(sdwan["authority"]),
        "manager-tenant:default",
        "change-b",
        native,
    )


def _aci_acl_event(
    registry: Mapping[str, Any], schedule_id: str, event_epoch: int
) -> dict[str, Any]:
    aci = registry["aci"]
    primary = registry["primary"]
    backend = primary["backend"]
    database = primary["database"]
    permit = "permit" in schedule_id
    source_port = 43002 if "recovery" in schedule_id else 43000 if permit else 43001
    source_mac = str(aci["source_endpoint_mac"])
    target_mac = str(aci["database_endpoint_mac"])
    apic_host = str(aci["authority"]).removeprefix("https://").split("/", 1)[0]
    timestamp = _iso(event_epoch, "offset_ms")
    number = 100 + _stable_int(schedule_id, "aci-acl-record", modulus=900_000)
    action = "acllogPermitL3Pkt" if permit else "acllogDropL3Pkt"
    action_prefix = "permitl3pkt" if permit else "dropl3pkt"
    leaf_dn = f"topology/pod-{aci['pod_id']}/node-{aci['leaf_node_id']}/ndbgs/acllog/tn-{aci['tenant']}/ctx-{aci['vrf']}/{action_prefix}-{number}-smac-{source_mac}-dmac-{target_mac}-time-{timestamp}"
    attrs = [
        ("childAction", ""),
        ("dn", leaf_dn),
        ("dstEpgName", str(aci["provider_epg_dn"])),
        ("dstIp", str(database["ip"])),
        ("dstMacAddr", target_mac),
        ("dstPcTag", aci["provider_pc_tag"]),
        ("dstPort", int(database["port"])),
        ("lcOwn", "local"),
        ("modTs", timestamp),
        ("pktLen", 60),
        ("protocol", "tcp"),
        ("recordId", number),
        ("srcEpgName", str(aci["consumer_epg_dn"])),
        ("srcIntf", str(aci["leaf_interface"])),
        ("srcIp", str(backend["ip"])),
        ("srcMacAddr", source_mac),
        ("srcPcTag", aci["consumer_pc_tag"]),
        ("srcPort", source_port),
        ("status", ""),
        ("timeStamp", timestamp),
        ("vrfEncap", f"vxlan-{aci['vrf_vnid']}"),
    ]
    return _envelope(
        event_epoch,
        HEAVY_FORWARDER,
        "cisco_nexus_aci://classInfo_fvRsCEpToPathEp",
        "cisco:dc:aci:class",
        "cisco_dc",
        _aci_raw(event_epoch, attrs, apic_host, action),
    )


def _nxos_events(registry: Mapping[str, Any], event_epoch: int) -> list[dict[str, Any]]:
    fabric = registry["fabric"]
    at = _utc(event_epoch).strftime("%Y-%m-%d %H:%M:%S")
    device = f"{fabric['management_ip']}:443"
    common = {"timestamp": at, "device": device}
    records = [
        (
            "nxhostname",
            "cisco_nexus_9k://nxhostname",
            [{"hostname": str(fabric["chassis_alias"])}],
        ),
        (
            "nxversion",
            "cisco_nexus_9k://nxversion",
            [
                {"nxos_ver_str": str(fabric["nxos_version"])},
                {"proc_board_id": str(fabric["chassis_serial"])},
            ],
        ),
        (
            "nxinterface",
            "cisco_nexus_9k://nxinterface",
            {
                "interface": str(fabric["interface"]),
                "state": "up",
                "admin_state": "up",
                "share_state": "Dedicated",
                "desc": "checkout client attachment",
                "eth_hw_desc": "Ethernet interface",
                "eth_hw_addr": "02:61:FF:00:00:61",
                "eth_bia_addr": "02:61:FF:00:00:61",
                "eth_mtu": "9216",
                "eth_bw": 25000000,
                "eth_duplex": "full",
                "eth_speed": "25 Gb/s",
                "medium": "broadcast",
            },
        ),
    ]
    return [
        _envelope(
            event_epoch,
            HEAVY_FORWARDER,
            source,
            "cisco:dc:nexus9k",
            "cisco_dc",
            json.dumps(
                {**common, "component": component, "Row_info": row}, ensure_ascii=False
            ),
        )
        for component, source, row in records
    ]


def _aci_text_attributes(raw: str) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for token in raw.split("\t")[1:]:
        key, separator, value = token.partition("=")
        if not separator:
            continue
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        attributes[key] = value
    return attributes


def _readback_native_selector(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Describe a source-native selector; never claim it is a Splunk receipt ID."""

    sourcetype = str(envelope["sourcetype"])
    event = envelope["event"]
    if isinstance(event, str):
        try:
            payload = json.loads(event)
        except json.JSONDecodeError:
            payload = None
    else:
        payload = event

    if sourcetype == "otel:traces" and isinstance(payload, Mapping):
        return {
            "kind": "otel_trace_span",
            "fields": {
                "trace_id": payload.get("trace_id"),
                "span_id": payload.get("span_id"),
            },
        }
    if sourcetype == "stream:netflow" and isinstance(payload, Mapping):
        return {
            "kind": "source_tuple_and_export_sequence",
            "fields": {
                key: payload[key]
                for key in (
                    "exporter_ip",
                    "observation_domain_id",
                    "seqnumber",
                    "src_ip",
                    "src_port",
                    "dest_ip",
                    "dest_port",
                    "protoid",
                )
                if key in payload
            },
        }
    if sourcetype == "cilium:hubble:flow" and isinstance(payload, Mapping):
        flow = payload.get("flow", {})
        return {
            "kind": "hubble_native_uuid",
            "fields": {"flow.uuid": flow.get("uuid")}
            if isinstance(flow, Mapping)
            else {},
        }
    if sourcetype == "cisco:sfw:estreamer" and isinstance(payload, Mapping):
        return {
            "kind": "ftd_source_tuple_and_connection_selector",
            "fields": {
                key: payload[key]
                for key in (
                    "SourceHost",
                    "DeviceIP",
                    "ConnectionID",
                    "FirstPacketSecond",
                    "InitiatorIP",
                    "InitiatorPort",
                    "ResponderIP",
                    "ResponderPort",
                    "AC_RuleAction",
                )
                if key in payload
            },
        }
    if sourcetype == "meraki:accesspoints" and isinstance(payload, Mapping):
        return {
            "kind": "meraki_association_native_fields",
            "fields": {
                key: payload[key]
                for key in (
                    "organizationId",
                    "networkId",
                    "occurredAt",
                    "clientMac",
                    "deviceSerial",
                    "ssidNumber",
                )
                if key in payload
            },
        }
    if sourcetype == "meraki:devices" and isinstance(payload, Mapping):
        return {
            "kind": "meraki_device_serial",
            "fields": {"serial": payload.get("serial")},
        }
    if sourcetype == "cisco:dnac:client" and isinstance(payload, Mapping):
        return {
            "kind": "catalyst_client_mac_and_snapshot_time",
            "fields": {
                "macAddress": payload.get("macAddress"),
                "lastUpdatedTime": payload.get("lastUpdatedTime"),
            },
        }
    if sourcetype.startswith("kube:object:") and isinstance(payload, Mapping):
        obj = payload.get("object", {})
        metadata = obj.get("metadata", {}) if isinstance(obj, Mapping) else {}
        return {
            "kind": "kubernetes_native_uid_and_resource_version",
            "fields": {
                "type": payload.get("type"),
                "kind": obj.get("kind") if isinstance(obj, Mapping) else None,
                "metadata.uid": metadata.get("uid")
                if isinstance(metadata, Mapping)
                else None,
                "metadata.resourceVersion": metadata.get("resourceVersion")
                if isinstance(metadata, Mapping)
                else None,
            },
        }
    if sourcetype in {"cisco:dc:aci:class", "cisco:dc:aci:stats"} and isinstance(
        event, str
    ):
        attributes = _aci_text_attributes(event)
        return {
            "kind": "aci_native_dn_and_component",
            "fields": {
                "dn": attributes.get("dn"),
                "component": attributes.get("component"),
            },
        }
    return {"kind": "payload_sha256_only", "fields": {}}


def _normalized_profile_source(envelope: Mapping[str, Any]) -> str | None:
    return {
        "stream:netflow": "stream_ipfix",
        "meraki:accesspoints": "meraki_association",
        "cisco:dnac:client": "catalyst_client_snapshot",
    }.get(str(envelope.get("sourcetype")))


def _native_event_id(selector: Mapping[str, Any]) -> tuple[str, str] | None:
    fields = selector.get("fields", {})
    if not isinstance(fields, Mapping):
        return None
    kind = selector.get("kind")
    path = {
        "otel_trace_span": "span_id",
        "hubble_native_uuid": "flow.uuid",
        "meraki_device_serial": "serial",
        "kubernetes_native_uid_and_resource_version": "metadata.uid",
        "aci_native_dn_and_component": "dn",
    }.get(str(kind))
    value = fields.get(path) if path else None
    if isinstance(value, str) and value:
        return str(kind), value
    return None


def _raw_readback_expectations(
    raw_events: list[dict[str, Any]], execution_id: str, schedule_id: str
) -> list[dict[str, Any]]:
    selector_counts = Counter(
        (
            str(item["index"]),
            str(item["sourcetype"]),
            str(item["source"]),
            str(item["host"]),
        )
        for item in raw_events
    )
    expected: list[dict[str, Any]] = []
    for ordinal, item in enumerate(raw_events, start=1):
        selector = _readback_native_selector(item)
        row: dict[str, Any] = {
            "readback_key": _readback_key(execution_id, schedule_id, "hec", ordinal),
            "ordinal": ordinal,
            "ordinal_count": len(raw_events),
            "expected_count": selector_counts[
                (
                    str(item["index"]),
                    str(item["sourcetype"]),
                    str(item["source"]),
                    str(item["host"]),
                )
            ],
            "index": item["index"],
            "sourcetype": item["sourcetype"],
            "hec_source": item["source"],
            "host": item["host"],
            "native_event_selector": selector,
            "native_payload_sha256": _payload_sha256(item["event"]),
            "native_payload_sha256_algorithm": "utf8-raw-v1"
            if isinstance(item["event"], str)
            else "native-json-sort-keys-v1",
            **({"indexed_fields": dict(item["fields"])} if item.get("fields") else {}),
        }
        native_id = _native_event_id(selector)
        if native_id is not None:
            row["native_event_id_kind"], row["native_event_id"] = native_id
        normalized_source = _normalized_profile_source(item)
        if normalized_source is not None:
            row["normalized_profile_source"] = normalized_source
        if item["sourcetype"] == "cisco:sfw:estreamer":
            payload = json.loads(item["event"])
            row["native_payload_source"] = {
                "field": "SourceHost",
                "value": payload["SourceHost"],
            }
        expected.append(row)
    return expected


def _materialize_one(
    scenario: Mapping[str, Any], registry: Mapping[str, Any], item: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    schedule_id = str(item["id"])
    raw: list[dict[str, Any]] = []
    native: list[dict[str, Any]] = []
    notes: list[str] = []

    if re.fullmatch(
        r"[ab]-(primary|control)-binding-(prelude|baseline|change|impact|recovery)",
        schedule_id,
    ):
        which = "control" if "-control-" in schedule_id else "primary"
        raw.append(
            _internal_binding_span(
                scenario,
                registry,
                which,
                _event_time(item),
                schedule_id,
                str(registry["execution_id"]),
            )
        )
    elif schedule_id in {"a-connected-k8s-prelude", "b-connected-k8s-prelude"}:
        native_events, raw_events = _connected_pod_inputs_and_events(
            scenario, registry, _event_time(item)
        )
        native.extend(native_events)
        raw.extend(raw_events)
    elif re.fullmatch(
        r"[ab]-(inventory|pricing)-binding-(prelude|baseline|change|impact|recovery)",
        schedule_id,
    ):
        which = "inventory" if "-inventory-" in schedule_id else "pricing"
        raw.append(
            _internal_binding_span(
                scenario,
                registry,
                which,
                _event_time(item),
                schedule_id,
                str(registry["execution_id"]),
            )
        )
    elif schedule_id in {
        "a-inventory-baseline-flow",
        "a-pricing-baseline-flow",
        "b-inventory-baseline-flow",
        "b-pricing-baseline-flow",
    }:
        raw.append(
            _connected_hubble_event(scenario, registry, schedule_id, _event_time(item))
        )
    elif schedule_id == "a-nxos-context":
        raw.extend(_nxos_events(registry, _event_time(item)))
    elif schedule_id in {"a-ssid-prelude", "a-ssid-baseline"}:
        native.append(
            _meraki_ssid_input(
                registry, "change-a", "primary_network_id", "defaultVlanId_baseline"
            )
        )
    elif schedule_id == "a-ssid-change-poll":
        native.append(
            _meraki_ssid_input(
                registry, "change-a", "primary_network_id", "defaultVlanId_impact"
            )
        )
    elif schedule_id == "a-ssid-restore-poll":
        native.append(
            _meraki_ssid_input(
                registry, "change-a", "primary_network_id", "defaultVlanId_restored"
            )
        )
    elif schedule_id in {"a-k8s-primary-prelude", "a-k8s-control-prelude"}:
        native_events, raw_events = _kubernetes_inputs_and_events(
            scenario,
            registry,
            "control" if "control" in schedule_id else "primary",
            _event_time(item),
        )
        native.extend(native_events)
        raw.extend(raw_events)
    elif schedule_id in {"a-rollout-k8s-update", "b-backend-k8s-update"}:
        native_events, raw_events = _kubernetes_inputs_and_events(
            scenario,
            registry,
            "primary",
            _event_time(item),
            backend_key="backend_v2",
            update_watch=True,
        )
        native.extend(native_events)
        raw.extend(raw_events)
    elif schedule_id == "a-control-inventory":
        inventory_events, inventory_limitations = _meraki_inventory_events(
            registry, _event_time(item)
        )
        raw.extend(inventory_events)
        notes.extend(inventory_limitations)
    elif schedule_id == "a-baseline-association":
        raw.append(
            _meraki_association(
                registry,
                client_key="primary",
                ap_key="primary_access_point",
                network_key="primary_network_id",
                event_epoch=_event_time(item),
            )
        )
    elif schedule_id == "a-control-association":
        raw.append(
            _meraki_association(
                registry,
                client_key="control",
                ap_key="control_access_point",
                network_key="control_network_id",
                event_epoch=_event_time(item),
            )
        )
    elif schedule_id == "a-reused-association":
        raw.append(_meraki_reused_association(registry, _event_time(item)))
    elif schedule_id in {
        "a-baseline-connection",
        "a-control-connection",
        "a-impact-connection",
        "a-recovery-connection",
        "a-nat-source-observation",
        "a-rollout-baseline-connection",
        "a-rollout-impact-connection",
        "a-rollout-recovery-connection",
    }:
        raw.append(_ftd_event(scenario, schedule_id, _event_time(item)))
    elif schedule_id in {
        "a-baseline-flow",
        "a-control-flow",
        "a-recovery-flow",
        "a-nat-downstream-flow",
        "a-rollout-baseline-flow",
        "a-rollout-impact-flow",
        "a-rollout-recovery-flow",
        "a-gap-impact-flow",
        "a-permission-impact-flow",
    } or schedule_id in {
        "b-baseline-client-connection",
        "b-baseline-client-flow",
        "b-impact-frontend-flow",
        "b-backend-baseline-flow",
        "b-backend-impact-flow",
        "b-permission-impact-flow",
    }:
        raw.append(_stream_event(scenario, registry, schedule_id, _event_time(item)))
    elif schedule_id in {
        "b-nd-baseline-flow",
        "b-nd-impact-flow",
        "b-nd-recovery-flow",
    }:
        raw.append(_nd_flow_event(scenario, registry, schedule_id, _event_time(item)))
    elif schedule_id in {
        "a-baseline-handoff",
        "a-control-handoff",
        "a-recovery-handoff",
        "a-rollout-impact-handoff",
        "a-rollout-recovery-handoff",
        "a-gap-impact-handoff",
        "a-permission-impact-handoff",
        "b-baseline-client-handoff",
        "b-impact-frontend-handoff",
        "b-backend-impact-handoff",
        "b-permission-impact-handoff",
        "b-recovery-client-handoff",
    }:
        raw.append(_hubble_event(scenario, registry, schedule_id, _event_time(item)))
    elif schedule_id in {"a-network-audit-context", "a-restore-audit-context"}:
        native.append(
            _meraki_audit_input(
                registry,
                scope="change-a",
                network_key="primary_network_id",
                event_epoch=_event_time(item),
                schedule_id=schedule_id,
            )
        )
        notes.append(
            "Meraki network audit is context only; no SSID object, actor, or applied-time link is supplied."
        )
    elif schedule_id == "a-unrelated-network-change":
        native.append(
            _meraki_audit_input(
                registry,
                scope="change-a-other",
                network_key="unrelated_network_id",
                event_epoch=_event_time(item),
                schedule_id=schedule_id,
            )
        )
    elif schedule_id == "b-aci-prelude":
        native.extend(_aci_policy_inputs(registry, scope="change-b", narrowed=False))
        raw.extend(_aci_endpoint_events(registry, _event_time(item)))
    elif schedule_id in {
        "b-aci-endpoint-prelude",
        "b-aci-endpoint-update",
    }:
        native_event, raw_event = _aci_endpoint_snapshot(
            scenario,
            registry,
            _event_time(item),
            updated=schedule_id.endswith("update"),
        )
        native.append(native_event)
        raw.append(raw_event)
    elif schedule_id in {"b-catalyst-client-snapshot"}:
        raw.append(_catalyst_client_event(scenario, registry, _event_time(item)))
    elif schedule_id == "b-k8s-prelude":
        native_events, raw_events = _kubernetes_inputs_and_events(
            scenario, registry, "primary", _event_time(item)
        )
        native.extend(native_events)
        raw.extend(raw_events)
    elif (
        schedule_id == "b-baseline-database-permit"
        or schedule_id == "b-impact-database-drop"
        or schedule_id == "b-recovery-database-permit"
    ):
        raw.append(_aci_acl_event(registry, schedule_id, _event_time(item)))
    elif schedule_id in {"b-policy-edit-audit", "b-policy-restore-audit"}:
        native.append(_aci_audit_input(registry, schedule_id, _event_time(item)))
    elif schedule_id == "b-policy-change-poll":
        native.extend(_aci_policy_inputs(registry, scope="change-b", narrowed=True))
    elif schedule_id == "b-policy-restore-poll":
        native.extend(_aci_policy_inputs(registry, scope="change-b", narrowed=False))
    elif schedule_id == "b-unrelated-wan-change":
        native.append(_sdwan_audit_input(registry, _event_time(item)))
        notes.append(
            "SD-WAN audit remains unresolved context: the native row has no site, VPN, policy, or usable device-target binding."
        )
    else:
        notes.append(
            f"No source materializer is defined for {item.get('product')}/{item.get('family')}; no fact was emitted."
        )

    return raw, native, notes


def _validate_inputs(
    scenario: Mapping[str, Any], run_plan: Mapping[str, Any]
) -> list[dict[str, Any]]:
    scenario_id = _require_text(scenario.get("scenario_id"), "scenario_id")
    if scenario_id not in SCENARIO_IDS:
        raise SourceMaterializationError(
            "Only the two reviewed demo scenario IDs are supported."
        )
    if run_plan.get("scenario_id") != scenario_id:
        raise SourceMaterializationError(
            "Run plan scenario_id does not match the template."
        )
    if run_plan.get("template_revision") != scenario.get("template_revision"):
        raise SourceMaterializationError(
            "Run plan template revision does not match the template."
        )
    if run_plan.get("template_sha256") != _sha256(scenario):
        raise SourceMaterializationError(
            "Run plan template_sha256 does not match the template."
        )
    if (
        run_plan.get("variant_id") != scenario.get("variant_id")
        or run_plan.get("variant_contract_version")
        != scenario.get("variant_contract_version")
        or run_plan.get("variant_expectation") != scenario.get("variant_expectation")
        or run_plan.get("template_sha256") != _sha256(scenario)
    ):
        raise SourceMaterializationError(
            "Run plan does not bind the selected scenario variant."
        )
    execution_id = run_plan.get("execution_id")
    try:
        if str(uuid.UUID(execution_id)) != execution_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise SourceMaterializationError(
            "Run plan execution_id must be a UUID."
        ) from exc
    plan_hash = run_plan.get("plan_sha256")
    if not isinstance(plan_hash, str) or not _HASH_RE.fullmatch(plan_hash):
        raise SourceMaterializationError(
            "Run plan must carry a lowercase SHA-256 plan_sha256."
        )
    body = {key: value for key, value in run_plan.items() if key != "plan_sha256"}
    if _sha256(canonical_json(body)) != plan_hash:
        raise SourceMaterializationError("Run plan content does not match plan_sha256.")
    anchor = run_plan.get("anchor_t_epoch")
    if isinstance(anchor, bool) or not isinstance(anchor, int) or anchor < 0:
        raise SourceMaterializationError(
            "Run plan anchor_t_epoch must be a non-negative integer."
        )
    template_items = scenario.get("evidence_schedule")
    plan_items = run_plan.get("schedule")
    if not isinstance(template_items, list) or not isinstance(plan_items, list):
        raise SourceMaterializationError(
            "Scenario and run plan schedules must be arrays."
        )
    template_by_id = {
        item.get("id"): item for item in template_items if isinstance(item, Mapping)
    }
    plan_by_id = {
        item.get("id"): item for item in plan_items if isinstance(item, Mapping)
    }
    if len(template_by_id) != len(template_items) or len(plan_by_id) != len(plan_items):
        raise SourceMaterializationError(
            "Scenario and run-plan schedule IDs must be unique objects."
        )
    if set(template_by_id) != set(plan_by_id):
        raise SourceMaterializationError(
            "Run plan schedule IDs differ from the scenario template."
        )
    for schedule_id, template_item in template_by_id.items():
        plan_item = plan_by_id[schedule_id]
        for key in ("product", "family", "required", "status"):
            if plan_item.get(key) != template_item.get(key):
                raise SourceMaterializationError(
                    f"Run-plan event {schedule_id} differs at {key}."
                )
        for key in (
            "collection_status",
            "collection_pages_expected",
            "collection_pages_received",
        ):
            if plan_item.get(key) != template_item.get(key):
                raise SourceMaterializationError(
                    f"Run-plan event {schedule_id} differs at {key}."
                )
        for actual_key in (
            "actual_emission_epoch",
            "transport_acknowledgment_epoch",
            "indexed_receipt_epoch",
            "readback_epoch",
        ):
            if plan_item.get(actual_key) is not None:
                raise SourceMaterializationError(
                    "Immutable source plan cannot contain actual timing or readback values."
                )
        if "offset_seconds" in template_item:
            expected = anchor + int(template_item["offset_seconds"])
            if plan_item.get("planned_source_epoch") != expected:
                raise SourceMaterializationError(
                    f"Run-plan source time differs for {schedule_id}."
                )
        else:
            start = anchor + int(template_item["window_start_offset_seconds"])
            end = anchor + int(template_item["window_end_offset_seconds"])
            if (
                plan_item.get("planned_collection_start_epoch") != start
                or plan_item.get("planned_collection_end_epoch") != end
            ):
                raise SourceMaterializationError(
                    f"Run-plan collection interval differs for {schedule_id}."
                )
    return [dict(item) for item in plan_items]


def materialize_source_events(
    scenario: Mapping[str, Any], run_plan: Mapping[str, Any]
) -> dict[str, Any]:
    """Return deterministic raw facts and native input recipes for a validated plan.

    ``raw_events`` are complete HEC envelopes with the exact host, source,
    sourcetype and index required for a later source-bound readback. ``native_inputs``
    are API-shaped payloads plus authority, native partition and independent
    routing scope. They intentionally contain no collection receipt metadata;
    the runner must attach that only after the actual collection/readback step.
    """

    plan_items = _validate_inputs(scenario, run_plan)
    return {
        **_materialize_inputs(
            scenario,
            plan_items,
            str(run_plan["execution_id"]),
            variant_registry_sha256=run_plan["variant_registry_sha256"],
        ),
        "plan_sha256": run_plan["plan_sha256"],
    }


def prepare_source_inputs(
    scenario: Mapping[str, Any], *, execution_id: str, anchor_epoch: int
) -> dict[str, Any]:
    """Freeze source inputs before inventory and final plan creation.

    This pure preparation is neither a run plan nor permission to emit. The
    finalized plan must use the same UUID, anchor, template and exact input bytes.
    No inventory/plan placeholder or actual collection clock is manufactured.
    """
    from tools.change_scenarios_v2 import validate_scenario

    validate_scenario(scenario)
    try:
        if str(uuid.UUID(execution_id)) != execution_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise SourceMaterializationError(
            "execution_id must be a canonical UUID."
        ) from exc
    if (
        isinstance(anchor_epoch, bool)
        or not isinstance(anchor_epoch, int)
        or not 120 <= anchor_epoch <= 253_402_299_599
    ):
        raise SourceMaterializationError("anchor_epoch must be an integer UTC epoch.")
    items = []
    for item in scenario["evidence_schedule"]:
        prepared = {
            key: item[key] for key in ("id", "product", "family", "required", "status")
        }
        for optional_key in (
            "collection_status",
            "collection_pages_expected",
            "collection_pages_received",
        ):
            if optional_key in item:
                prepared[optional_key] = item[optional_key]
        prepared["planned_source_time_basis"] = "synthetic_scenario_clock"
        if "offset_seconds" in item:
            prepared["planned_source_epoch"] = anchor_epoch + item["offset_seconds"]
        else:
            prepared["planned_collection_start_epoch"] = (
                anchor_epoch + item["window_start_offset_seconds"]
            )
            prepared["planned_collection_end_epoch"] = (
                anchor_epoch + item["window_end_offset_seconds"]
            )
        items.append(prepared)
    items.sort(
        key=lambda item: (
            item.get(
                "planned_source_epoch", item.get("planned_collection_start_epoch")
            ),
            item["id"],
        )
    )
    from tools.change_scenarios_v2 import variant_registry_hash

    return _materialize_inputs(
        scenario,
        items,
        execution_id,
        variant_registry_sha256=variant_registry_hash(),
    )


def _whole_native_epoch(value: Any, *, integer=False) -> int:
    if integer:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        raise SourceMaterializationError("Modeled FTD clock must be a native integer.")
    if not isinstance(value, str):
        raise SourceMaterializationError("Modeled native traffic clock is missing.")
    # The authored traffic facts use whole seconds. Reject an unreviewed
    # precision change instead of silently truncating native nanoseconds.
    match = re.fullmatch(
        r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(0{1,9}))?(Z|[+-]\d\d:\d\d)",
        value,
    )
    if match is None:
        raise SourceMaterializationError("Modeled native traffic clock is unsupported.")
    parsed = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
    return int(parsed.timestamp())


def assert_source_phase_buckets(
    scenario: Mapping[str, Any], source_inputs: Mapping[str, Any], *, anchor_epoch: int
) -> list[dict[str, Any]]:
    """Check each authored traffic record against the actual writer time model.

    This is a model check of synthetic source inputs, not an indexed receipt or
    claim that the supported writer has executed. It deliberately inspects the
    native end field rather than trusting the HEC timestamp or schedule label.
    """
    if (
        isinstance(anchor_epoch, bool)
        or not isinstance(anchor_epoch, int)
        or anchor_epoch % 300
    ):
        raise SourceMaterializationError(
            "Traffic phase checks require a UTC 300-second anchor."
        )
    traffic_families = {
        "connection_observation",
        "ms390_client_flow",
        "hubble_client_tuple",
        "hubble_pod_tuple",
        "catalyst_client_flow",
        "flow_observation",
    }
    schedule = {item["id"]: item for item in scenario["evidence_schedule"]}
    evidence = []
    for item in source_inputs["events"]:
        if item["family"] not in traffic_families or item["status"] != "planned":
            continue
        authored = schedule[item["id"]]
        offset = authored["offset_seconds"]
        phase = next(
            (
                phase
                for phase in scenario["clock"]["phases"]
                if phase["id"] == authored.get("summary_bucket_phase")
            ),
            None,
        )
        if (
            phase is None
            or not item["raw_events"]
            or not (
                phase["start_offset_seconds"] <= offset < phase["end_offset_seconds"]
            )
        ):
            raise SourceMaterializationError(
                "Traffic source lacks its authored phase or facts."
            )
        for raw, expected in zip(
            item["raw_events"], item["readback_expected"], strict=True
        ):
            payload = raw["event"]
            if isinstance(payload, str) and raw["sourcetype"] != "cisco:dc:aci:class":
                payload = json.loads(payload)
            if raw["sourcetype"] == "stream:netflow":
                field, native_end = "endtime", payload["endtime"]
            elif raw["sourcetype"] == "cisco:sfw:estreamer":
                # adm_flows_ftd deliberately uses the connection-open instant
                # as both start/end, even if another packet clock is present.
                field, native_end = "FirstPacketSecond", payload["FirstPacketSecond"]
            elif raw["sourcetype"] == "cilium:hubble:flow":
                field, native_end = "flow.time", payload["flow"]["time"]
            elif raw["sourcetype"] == "cisco:dc:aci:class" and isinstance(payload, str):
                attributes = _aci_text_attributes(payload)
                if attributes.get("component") not in {
                    "acllogPermitL3Pkt",
                    "acllogDropL3Pkt",
                }:
                    raise SourceMaterializationError(
                        "Traffic record is not a supported native ACI ACL observation."
                    )
                field, native_end = "timeStamp", attributes["timeStamp"]
            elif raw["sourcetype"] == "cisco:dc:nd:flows":
                field, native_end = "ts", payload["ts"]
            else:
                raise SourceMaterializationError(
                    "Traffic source has no reviewed writer clock model."
                )
            epoch = _whole_native_epoch(
                native_end, integer=raw["sourcetype"] == "cisco:sfw:estreamer"
            )
            start_field = (
                "timestamp" if raw["sourcetype"] == "stream:netflow" else field
            )
            start_epoch = (
                _whole_native_epoch(payload["timestamp"])
                if raw["sourcetype"] == "stream:netflow"
                else epoch
            )
            bucket = epoch // 300 * 300
            expected_receipt = (
                ((epoch // 300) + 1) * 300
                if raw["sourcetype"] == "cisco:dc:nd:flows"
                else epoch
            )
            if (
                start_epoch != epoch
                or raw["time"] != expected_receipt
                or epoch != anchor_epoch + offset
                or not (
                    anchor_epoch + phase["start_offset_seconds"]
                    <= bucket
                    < anchor_epoch + phase["end_offset_seconds"]
                )
            ):
                raise SourceMaterializationError(
                    "Native traffic end/bucket falls outside its intended phase."
                )
            evidence.append(
                {
                    "schedule_id": item["id"],
                    "readback_key": expected["readback_key"],
                    "sourcetype": raw["sourcetype"],
                    "native_start_time_field": start_field,
                    "native_end_time_field": field,
                    "modeled_adm_start_epoch": start_epoch,
                    "modeled_adm_end_epoch": epoch,
                    "bucket_epoch": bucket,
                    "phase_id": phase["id"],
                }
            )
    return evidence


def _materialize_inputs(
    scenario: Mapping[str, Any],
    plan_items: list[dict[str, Any]],
    execution_id: str,
    *,
    variant_registry_sha256: str,
) -> dict[str, Any]:
    scenario_id = _require_text(scenario.get("scenario_id"), "scenario_id")
    registry = materialize_identity_registry(scenario)
    registry["execution_id"] = execution_id
    routing_profiles = build_source_profiles(scenario, registry)
    schedule_by_id = {item["id"]: item for item in scenario["evidence_schedule"]}
    events: list[dict[str, Any]] = []
    global_limitations: list[str] = []

    for plan_item in plan_items:
        schedule_id = str(plan_item["id"])
        event: dict[str, Any] = {
            "id": schedule_id,
            "product": plan_item["product"],
            "family": plan_item["family"],
            "required": plan_item["required"],
            "status": plan_item["status"],
            "planned_source_time_basis": plan_item["planned_source_time_basis"],
            "raw_events": [],
            "readback_expected": [],
            "raw_event_expected_count": 0,
            "native_inputs": [],
            "limitations": [],
        }
        for optional_key in (
            "collection_status",
            "collection_pages_expected",
            "collection_pages_received",
        ):
            if optional_key in plan_item:
                event[optional_key] = plan_item[optional_key]
        if "planned_source_epoch" in plan_item:
            event["planned_source_epoch"] = plan_item["planned_source_epoch"]
        if plan_item["family"] == "internal_service_workload":
            event["minimum_emission_epoch"] = event["planned_source_epoch"] + 0.001
        elif plan_item["family"] == "flow_observation" and plan_item["product"] == "nd":
            # ND's collector stamps HEC receipt at the next five-minute poll;
            # delivery must occur at that receipt boundary, not before it.
            event["minimum_emission_epoch"] = (
                (event["planned_source_epoch"] // 300) + 1
            ) * 300
        if "planned_collection_start_epoch" in plan_item:
            event["planned_collection_start_epoch"] = plan_item[
                "planned_collection_start_epoch"
            ]
            event["planned_collection_end_epoch"] = plan_item[
                "planned_collection_end_epoch"
            ]
        try:
            raw_events, native_inputs, notes = _materialize_one(
                scenario,
                registry,
                schedule_by_id[schedule_id]
                | {
                    key: event[key]
                    for key in (
                        "planned_source_epoch",
                        "planned_collection_start_epoch",
                        "planned_collection_end_epoch",
                    )
                    if key in event
                },
            )
            event["raw_events"] = raw_events
            event["readback_expected"] = _raw_readback_expectations(
                raw_events, execution_id, schedule_id
            )
            event["raw_event_expected_count"] = len(raw_events)
            event["native_inputs"] = _decorate_native_inputs(
                native_inputs, execution_id, schedule_id
            )
            if "collection_pages_expected" in plan_item:
                for recipe in event["native_inputs"]:
                    recipe["expected_collection_shape"]["expected_page_count"] = (
                        plan_item["collection_pages_expected"]
                    )
            event["limitations"].extend(notes)
            global_limitations.extend(f"{schedule_id}: {note}" for note in notes)
        except _MissingFact as exc:
            event["limitations"].append(f"source fact unavailable: {exc}")
            global_limitations.append(f"{schedule_id}: source fact unavailable: {exc}")
        events.append(event)

    if scenario_id == "track-a-firewall":
        global_limitations.extend(
            [
                "FMC policy-edit and deployment evidence is a blocked variant and is not synthesized.",
                "No CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy schedule is present; neither policy kind is emitted.",
            ]
        )
    else:
        global_limitations.append(
            "SD-WAN audit is unresolved context: no native site, VPN, policy target, or usable device binding is present."
        )
        global_limitations.append(
            "No CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy schedule is present; neither policy kind is emitted."
        )
    global_limitations.append(
        "Generated values are documentation-shaped synthetic source facts, not live collection or source qualification."
    )

    output = {
        "schema_version": 1,
        "kind": SOURCE_PACKAGE_KIND,
        "scenario_id": scenario_id,
        "variant_id": scenario["variant_id"],
        "variant_contract_version": scenario["variant_contract_version"],
        "variant_expectation": scenario["variant_expectation"],
        "variant_registry_sha256": variant_registry_sha256,
        "template_sha256": _sha256(scenario),
        "execution_id": execution_id,
        "provenance": SOURCE_PROVENANCE,
        "identities": registry,
        "routing_profiles": routing_profiles,
        "events": events,
        "limitations": list(dict.fromkeys(global_limitations)),
    }
    _assert_no_fabricated_receipt_fields(output)
    return output


def _assert_no_fabricated_receipt_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        forbidden = _FORBIDDEN_RECIPE_KEYS.intersection(value)
        if forbidden:
            raise SourceMaterializationError(
                "Source recipes must not contain receipt, fingerprint, or effective-time fields."
            )
        for item in value.values():
            _assert_no_fabricated_receipt_fields(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_fabricated_receipt_fields(item)


__all__ = [
    "PROFILE_KEY",
    "SCENARIO_IDS",
    "SOURCE_PACKAGE_KIND",
    "SOURCE_PROVENANCE",
    "SourceMaterializationError",
    "build_source_profiles",
    "materialize_identity_registry",
    "materialize_source_events",
    "prepare_source_inputs",
    "native_payload_bytes",
    "native_payload_sha256",
    "assert_source_phase_buckets",
]
