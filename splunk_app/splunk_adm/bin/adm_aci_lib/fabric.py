"""Projection of a validated APIC poll into a bounded fabric inventory snapshot.

This contract is deliberately an inventory observation.  It does not assert
ownership, attachment, reachability, path traversal, or historical validity.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

from .validation import validate_events

SCHEMA = "application_atlas.aci_fabric_snapshot.v1"
MAX_DEVICES = 4096
MAX_LINKS = 16384
MAX_ROUTED_INTERFACES = 16384
MAX_SERIALIZED_BYTES = 16 * 1024 * 1024
_NODE = re.compile(r"(?:^|/)pod-(?P<pod>[^/]+)/node-(?P<node>[^/]+)(?:/|$)")


def _id(authority: str, fabric: str, native: str) -> str:
    return (
        "aci-device:"
        + hashlib.sha256(
            json.dumps([authority, fabric, native], separators=(",", ":")).encode()
        ).hexdigest()
    )


def _link_id(
    authority: str, fabric: str, capture_id: str, attrs: dict[str, Any]
) -> str:
    value = [
        authority,
        fabric,
        capture_id,
        attrs["dn"],
        attrs["n1"],
        attrs["p1"],
        attrs["n2"],
        attrs["p2"],
    ]
    return (
        "aci-link:"
        + hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()
    )


def project_fabric_snapshot(
    events: list[dict[str, Any]],
    profile: dict[str, Any],
    *,
    receipts: dict[tuple[Any, ...], float],
    as_of: float,
) -> dict[str, Any]:
    """Validate and project APIC objects into one snapshot row payload."""
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
    manifest = next(item for item in events if item.get("record_type") == "manifest")
    devices: list[dict[str, Any]] = []
    device_ids: dict[str, str] = {}
    for event in events:
        if event.get("record_type") != "object" or event.get("class") != "topSystem":
            continue
        attrs = event["attributes"]
        dn = attrs["dn"]
        match = _NODE.search(dn)
        if not match:
            raise ValueError("topSystem_dn_invalid")
        native = f"pod-{match.group('pod')}/node-{match.group('node')}"
        ident = _id(profile["authority"], profile["fabric"], native)
        if native in device_ids:
            raise ValueError("duplicate_device_identity")
        device_ids[native] = ident
        device_ids[match.group("node")] = ident
        device = {
            "id": ident,
            "authority": profile["authority"],
            "fabric": profile["fabric"],
            "native_id": native,
            "pod": match.group("pod"),
            "node": match.group("node"),
            "name": attrs.get("name") or native,
            "role": attrs.get("role", "unknown"),
            "source": "topSystem",
            "dn": dn,
        }
        optional_fields = {
            "oobMgmtAddr": "oob_mgmt_ip",
            "inbMgmtAddr": "inband_mgmt_ip",
            "address": "fabric_address",
            "serial": "serial",
        }
        for source, target in optional_fields.items():
            if source in attrs:
                if not isinstance(attrs[source], str) or not attrs[source]:
                    raise ValueError("topSystem_optional_invalid")
                device[target] = attrs[source]
        if "oob_mgmt_ip" in device:
            device["mgmt_ip"] = device["oob_mgmt_ip"]
        elif "inband_mgmt_ip" in device:
            device["mgmt_ip"] = device["inband_mgmt_ip"]
        devices.append(device)
    if len(devices) > MAX_DEVICES:
        raise ValueError("device_count_exceeds_bound")
    links: list[dict[str, Any]] = []
    for event in events:
        if event.get("record_type") != "object" or event.get("class") != "fabricLink":
            continue
        attrs = event["attributes"]
        required = ("dn", "n1", "n2", "s1", "s2", "p1", "p2")
        if (
            not isinstance(attrs.get("dn"), str)
            or not attrs["dn"]
            or any(
                isinstance(attrs.get(key), bool)
                or not isinstance(attrs.get(key), (str, int))
                or not str(attrs[key])
                for key in required[1:]
            )
        ):
            raise ValueError("fabric_link_endpoint_invalid")
        n1, n2 = str(attrs["n1"]), str(attrs["n2"])
        if n1 not in device_ids or n2 not in device_ids:
            raise ValueError("fabric_link_endpoint_missing")
        link = {
            "id": _link_id(
                profile["authority"], profile["fabric"], report["capture_id"], attrs
            ),
            "authority": profile["authority"],
            "fabric": profile["fabric"],
            "a_device": device_ids[n1],
            "b_device": device_ids[n2],
            "a_native_id": n1,
            "b_native_id": n2,
            "a_interface": f"eth{attrs['s1']}/{attrs['p1']}",
            "b_interface": f"eth{attrs['s2']}/{attrs['p2']}",
            "link_kind": "physical",
            "source": "fabricLink",
            "dn": attrs["dn"],
            "parallel_key": ":".join(sorted((n1, n2))),
        }
        links.append(link)
    if len(links) > MAX_LINKS:
        raise ValueError("link_count_exceeds_bound")
    physical, ethpm, routed = {}, {}, []
    for event in events:
        if event.get("record_type") != "object" or event.get("class") not in (
            "l1PhysIf",
            "ethpmPhysIf",
        ):
            continue
        attrs, dn = event["attributes"], event["attributes"]["dn"]
        suffix = "" if event["class"] == "l1PhysIf" else "/phys"
        match = re.fullmatch(
            r"(topology/pod-\d+/node-\d+/sys/phys-\[(eth\d+/\d+)\])"
            + re.escape(suffix),
            dn,
        )
        if match:
            if event["class"] == "l1PhysIf" and attrs.get(
                "id", match.group(2)
            ) != match.group(2):
                raise ValueError("physical_interface_id_mismatch")
            (physical if event["class"] == "l1PhysIf" else ethpm)[match.group(1)] = (
                attrs
            )
    for event in events:
        if event.get("record_type") != "object" or event.get("class") != "l3EncRtdIf":
            continue
        attrs, dn = event["attributes"], event["attributes"]["dn"]
        node_match = _NODE.search(dn)
        if not node_match:
            continue
        native = f"pod-{node_match.group('pod')}/node-{node_match.group('node')}"
        if native not in device_ids:
            raise ValueError("routed_interface_node_missing")
        if not all(
            isinstance(attrs.get(field), str) and attrs[field]
            for field in ("ifConnDn", "rtdOutDefDn")
        ):
            continue
        identifier = attrs.get("id")
        id_parent = re.fullmatch(r"(eth\d+/\d+)\.\d+", str(identifier))
        if not id_parent:
            continue  # Only physical Ethernet subinterfaces are supported here.
        parent = id_parent.group(1)
        expected_dn = (
            re.escape(f"topology/{native}/sys/ctx-[")
            + r"[^\]\r\n]+\]/encrtd-\["
            + re.escape(identifier)
            + r"\]"
        )
        if not re.fullmatch(expected_dn, dn):
            raise ValueError("routed_interface_dn_id_mismatch")
        out_match = re.fullmatch(
            r"resPolCont/rtdOutCont/rtdOutDef-\[uni/tn-[^/\[\]\s]+/out-[^/\[\]\s]+\]",
            attrs["rtdOutDefDn"],
        )
        if not out_match:
            continue
        conn_prefix = attrs["rtdOutDefDn"] + "/"
        if not attrs["ifConnDn"].startswith(conn_prefix):
            raise ValueError("routed_interface_connection_mismatch")
        conn_node = re.fullmatch(
            re.escape(attrs["rtdOutDefDn"])
            + r"/node-(\d+)/stpathatt-\[(eth\d+/\d+)\]/conndef/conn-\[(vlan-\d+)\]-\[([^\[\]\s]+)\]",
            attrs["ifConnDn"],
        )
        if not conn_node:
            raise ValueError("routed_interface_connection_invalid")
        if (
            conn_node.group(1) != node_match.group("node")
            or conn_node.group(2) != parent
        ):
            raise ValueError("routed_interface_node_mismatch")
        if (
            attrs.get("encap") != conn_node.group(3)
            or not 1 <= int(conn_node.group(3)[5:]) <= 4094
        ):
            raise ValueError("routed_interface_encap_mismatch")
        try:
            ipaddress.ip_interface(conn_node.group(4))
        except ValueError:
            raise ValueError("routed_interface_local_address_invalid") from None
        physical_dn = f"topology/pod-{node_match.group('pod')}/node-{node_match.group('node')}/sys/phys-[{parent}]"
        if physical_dn not in physical or physical_dn not in ethpm:
            continue
        item = {
            "id": f"{device_ids[native]}:{identifier}",
            "device": device_ids[native],
            "native_id": native,
            "interface": identifier,
            "parent_interface": parent,
            "dn": dn,
            "source": "l3EncRtdIf",
            "physical_dn": physical_dn,
            "physical_source": "l1PhysIf+ethpmPhysIf",
            "classification": "reported_routed_interface",
            "traversal": "not_observed",
            "layer": "routed_interface",
        }
        for source, target in (
            ("encap", "encap"),
            ("adminSt", "admin_state"),
            ("operSt", "oper_state"),
            ("ifConnDn", "connection_dn"),
            ("rtdOutDefDn", "routed_out_definition_dn"),
        ):
            if isinstance(attrs.get(source), str) and attrs[source]:
                item[target] = attrs[source]
        routed.append(item)
    if len(routed) > MAX_ROUTED_INTERFACES:
        raise ValueError("routed_interface_count_exceeds_bound")
    result = {
        "schema": SCHEMA,
        "classification": "inventory_snapshot",
        "qualification": "complete_two_pass_capture",
        "traversal": "not_observed",
        "authority": profile["authority"],
        "fabric": profile["fabric"],
        "scope": profile["scope"],
        "capture_id": report["capture_id"],
        "capture_started": manifest["capture_started_at"],
        "capture_completed": manifest["capture_completed_at"],
        "as_of": as_of,
        "receipt_time": max(receipts.values()) if receipts else None,
        "provenance": {
            "source": "atlas:aci_poll",
            "sourcetype": f"adm:aci_poll:v{profile.get('poll_version', '1')}",
            "index": profile["index"],
            "host": profile["host"],
            "apic_host": profile["apic_host"],
            "apic_pin": profile["apic_pin"],
            "capture_digest": manifest["capture_digest"],
        },
        "digest": manifest["capture_digest"],
        "device_count": len(devices),
        "link_count": len(links),
        "routed_interface_count": len(routed),
        "devices": devices,
        "links": links,
        "routed_interfaces": routed,
    }
    if (
        len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())
        > MAX_SERIALIZED_BYTES
    ):
        raise ValueError("snapshot_bytes_exceed_bound")
    return result
