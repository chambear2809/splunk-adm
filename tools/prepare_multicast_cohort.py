"""Convert a verified read-only NX-OS snapshot receipt to one Splunk HEC event.

Writes to stdout only. It does not contact devices or Splunk. It applies the same
structural limits as the Atlas parser (names, device, interface and adjacency counts,
event size). The profile's host, scope, index and validity range are deployment
settings the tool cannot see; Atlas rejects a cohort that does not match them.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re


def selector(value, pattern=r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}"):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("Invalid literal selector.")
    return value


def dict_rows(value, limit=512):
    """Return a list of objects, rejecting any other receipt shape."""
    if (
        not isinstance(value, list)
        or len(value) > limit
        or not all(isinstance(row, dict) for row in value)
    ):
        raise ValueError("Malformed receipt section.")
    return value


def build_event(receipt: dict, index: str, host: str) -> dict:
    if not isinstance(receipt, dict) or not isinstance(receipt.get("request"), dict):
        raise ValueError("Malformed receipt.")
    selector(index, r"[a-z][a-z0-9_-]{0,79}")
    selector(host)
    request = receipt["request"]
    if request["version"] != 1:
        raise ValueError("Unsupported forwarding receipt version.")
    scope = selector(request["scope"])
    if re.match(r"(?i)(unmapped|unknown|reserved|none)(:|$)", scope):
        raise ValueError("A verified scope is required.")
    group = ipaddress.IPv4Address(request["group"])
    sender = ipaddress.IPv4Address(request["sender"])
    if (
        not group.is_multicast
        or sender.is_multicast
        or sender.is_reserved
        or sender.is_loopback
        or sender.packed[0] == 0
    ):
        raise ValueError("Expected one IPv4 multicast group and unicast source.")
    observed = request["latest"]
    if (
        type(observed) is not int
        or not 0 < observed <= 253402300799
        or not receipt["collectionFrom"] <= observed <= receipt["collectionUntil"]
    ):
        raise ValueError("The snapshot anchor must fall within its capture window.")
    devices = {}
    for row in dict_rows(receipt["evidence"]):
        observer = selector(row["observer"])
        input_port = selector(row["input"])
        if (
            row["kind"] != "forwarding"
            or row["source"] != "device_state"
            or row["scope"] != scope
            or row["group"] != str(group)
            or row["sender"] != str(sender)
            or row["timestamp"] != observed
            or row["validUntil"] != observed
            or observer in devices
            or not isinstance(row["outputs"], list)
        ):
            raise ValueError("Device state does not belong to one point snapshot.")
        outputs = [selector(port) for port in row["outputs"]]
        if input_port in outputs or len(outputs) != len(set(outputs)):
            raise ValueError("Invalid device outgoing interfaces.")
        devices[observer] = {
            "observer": observer,
            "input": input_port,
            "outputs": outputs,
        }
    if (
        not 1 <= len(devices) <= 128
        or sum(len(row["outputs"]) for row in devices.values()) > 256
    ):
        raise ValueError("Device state exceeds the forwarding cohort limits.")

    links = []
    endpoints = set()
    checked = {
        ((row["from"], row["output"]), (row["to"], row["input"]))
        for row in dict_rows(receipt["comparisons"])
        if all(
            row.get(key) is True
            for key in (
                "reciprocal_cdp",
                "reciprocal_pim",
                "rpf_matches_upstream_interface_ip",
            )
        )
    }
    adjacency = dict_rows(receipt["adjacency"])
    # Same cap as the Atlas parser; a larger cohort would be rejected after indexing.
    if len(adjacency) > 256:
        raise ValueError("Device state exceeds the forwarding cohort limits.")
    for link in adjacency:
        if not isinstance(link.get("from"), dict) or not isinstance(
            link.get("to"), dict
        ):
            raise ValueError("Malformed adjacency.")
        src = (selector(link["from"]["observer"]), selector(link["from"]["interface"]))
        dst = (selector(link["to"]["observer"]), selector(link["to"]["interface"]))
        if (
            (src, dst) not in checked
            or link["scope"] != scope
            or link["validFrom"] != observed
            or link["validUntil"] != observed
            or src[0] == dst[0]
            or src[1] not in devices.get(src[0], {}).get("outputs", ())
            or dst[1] != devices.get(dst[0], {}).get("input")
            or src in endpoints
            or dst in endpoints
        ):
            raise ValueError(
                "Adjacency does not match verified route and interface evidence."
            )
        endpoints.update((src, dst))
        links.append(
            {
                "from": {"observer": src[0], "interface": src[1]},
                "to": {"observer": dst[0], "interface": dst[1]},
            }
        )
    event = {
        "schemaVersion": 1,
        "scope": scope,
        "group": str(group),
        "sender": str(sender),
        "observedAt": observed,
        "validUntil": observed,
        "devices": list(devices.values()),
        "adjacencies": links,
    }
    if len(json.dumps(event, separators=(",", ":")).encode()) > 65536:
        raise ValueError("Cohort exceeds the event size limit.")
    return {
        "time": observed,
        "index": index,
        "host": host,
        "sourcetype": "atlas:nxos:multicast:v1",
        "event": event,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--index", required=True)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        print(
            json.dumps(
                build_event(receipt, args.index, args.host), separators=(",", ":")
            )
        )
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        parser.exit(2, "Invalid or unsupported verified forwarding receipt.\n")


if __name__ == "__main__":
    main()
