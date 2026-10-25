"""Shared scenario types, constants, timestamps, network helpers, and output writing."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from datetime import timedelta
from datetime import timezone
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

RAW = ROOT / "fixtures" / "raw"

NS = uuid.UUID("6f0b7c3e-6a63-4a43-9c55-2f4a0d1e7b10")

HEAVY_FORWARDER = "splunk-hf-01"

STREAM_FORWARDER = "stream-fwd-01"

FMC_HOST = "192.0.2.70"

FTD_INPUT = "sbg_fw_estreamer_input://ftd_edge"

ISOVALENT_SOURCE = "http:isovalent"

CLUSTER_RECEIVER_NODE = "node-b"

EXPORTER_BOOT = datetime(2026, 9, 1, tzinfo=timezone.utc)

NETFLOW_INACTIVE_TIMEOUT_MS = 15000

VMM_CONTROLLER = "comp/prov-VMware/ctrlr-[vmm-shop]-vcenter-01"

POLL_INTERVAL = timedelta(minutes=5)

PROTO_NUMBER = {"icmp": 1, "tcp": 6, "udp": 17}

TCP_FLAGS_FULL_SESSION = 0x1B

MSS = 1460


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def epoch(dt: datetime) -> float:
    return round(dt.timestamp(), 6)


def epoch_ns(dt: datetime) -> int:
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 10**9 + delta.microseconds * 1000


def iso_us(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def iso_ms(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def iso_s(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_proto(dt: datetime) -> str:
    """Protobuf JSON Timestamp: 0, 3, 6 or 9 fractional digits."""
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    us = dt.microsecond
    if not us:
        return base + "Z"
    if us % 1000 == 0:
        return f"{base}.{us // 1000:03d}Z"
    return f"{base}.{us:06d}Z"


def naive_local(dt: datetime) -> str:
    # datetime.now().strftime("%Y-%m-%d %H:%M:%S%z") on a naive value; collector TZ assumed UTC.
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def endpoint(spec: str) -> tuple[str, int | None]:
    """'ip:port', or a bare IPv4 address for portless protocols such as ICMP."""
    if spec.count(":") == 1:
        ip, port = spec.rsplit(":", 1)
        return ip, int(port)
    return spec, None


def ipv4_mapped_full(ip: str) -> str:
    """Full-form, upper-case IPv4-mapped IPv6 literal (RFC 4291 section 2.5.5.2)."""
    a, b, c, d = (int(x) for x in ip.split("."))
    return f"0:0:0:0:0:FFFF:{a * 256 + b:04X}:{c * 256 + d:04X}"


TUNNEL_PORTS = {"vxlan": 8472, "geneve": 6081}


def legs(conv: dict) -> list[tuple[str, int, str, int, int]]:
    """Unidirectional (src_ip, src_port, dst_ip, dst_port, bytes) records of a conversation.

    Encapsulated traffic targets the tunnel port in both directions from a source port
    hashed from the inner flow (RFC 7348 section 5), so the reverse leg is not a mirror.
    """
    c_ip, c_port = endpoint(conv["client"])
    s_ip, s_port = endpoint(conv["server"])
    tunnel = TUNNEL_PORTS.get(conv.get("encapsulation", ""))
    if tunnel:
        reverse_port = 49152 + stable_int(conv["id"], "reverse", digits=5) % 16384
        return [
            (c_ip, c_port, s_ip, tunnel, conv["bytes_c2s"]),
            (s_ip, reverse_port, c_ip, tunnel, conv["bytes_s2c"]),
        ]
    return [
        (c_ip, c_port, s_ip, s_port, conv["bytes_c2s"]),
        (s_ip, s_port, c_ip, c_port, conv["bytes_s2c"]),
    ]


def segments(
    conv: dict, start: datetime, end: datetime
) -> list[tuple[datetime, datetime, float, bool]]:
    """(start, end, byte fraction, late) per exported record of one leg.

    A conversation with late_segment is exported as two records (active timeout); the second
    record reaches Splunk late and is written to fixtures/raw/late/.
    """
    if not conv.get("late_segment"):
        return [(start, end, 1.0, False)]
    mid = start + (end - start) / 2
    return [(start, mid, 0.5, False), (mid, end, 0.5, True)]


def packets(n_bytes: int) -> int:
    return max(1, math.ceil(n_bytes / MSS))


def stable_int(*parts: object, digits: int = 9) -> int:
    h = hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()
    return int(h[:12], 16) % 10**digits


def stable_hex(*parts: object, length: int = 64) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:length]


def derived_mac(ip: str) -> str:
    octets = [int(x) for x in ip.split(".")]
    return "02:00:" + ":".join(f"{o:02X}" for o in octets)


def polls(start: datetime, end: datetime) -> list[datetime]:
    out, t = [], start
    while t <= end:
        out.append(t)
        t += POLL_INTERVAL
    return out


def next_poll(dt: datetime) -> datetime:
    floor = dt.replace(second=0, microsecond=0)
    floor -= timedelta(minutes=floor.minute % 5)
    return floor + POLL_INTERVAL


def envelope(time, host, source, sourcetype, index, event, fields=None) -> dict:
    env = {
        "time": time,
        "host": host,
        "source": source,
        "sourcetype": sourcetype,
        "index": index,
        "event": event,
    }
    if fields:
        env["fields"] = fields
    return env


class Scenario:
    def __init__(self, doc: dict):
        self.doc = doc
        self.window_start = parse(doc["window"]["start"])
        self.window_end = parse(doc["window"]["end"])
        k8s = doc["kubernetes"]
        self.cluster = k8s["cluster"]
        self.nodes = {n["name"]: n for n in k8s["nodes"]}
        self.node_by_ip = {n["ip"]: n for n in k8s["nodes"]}
        self.pods = k8s["pods"]
        nd = doc["nexus_dashboard"]
        self.switches = {s["name"]: s for s in nd["switches"]}
        self.ifindex = {
            (i["device"], i["name"]): i["snmp_ifindex"] for i in nd["interfaces"]
        }
        self.uplinks = {
            i["device"]: i["name"]
            for i in nd["interfaces"]
            if i["description"].startswith("uplink")
        }
        self.env = doc["otel"]["environment"]

    def pod_at(self, ip: str, at: datetime) -> dict | None:
        for p in self.pods:
            end = parse(p["end"]) if p["end"] else None
            if p["ip"] == ip and parse(p["start"]) <= at and (end is None or at < end):
                return p
        return None

    def attachment(self, ip: str, at: datetime) -> tuple[str, str] | None:
        """(leaf, interface) where an address attaches to the NX-OS fabric."""
        pod = self.pod_at(ip, at)
        node = self.nodes[pod["node"]] if pod else self.node_by_ip.get(ip)
        return (node["leaf"], node["interface"]) if node else None

    def local_interface(self, leaf: str, ip: str, at: datetime) -> str:
        att = self.attachment(ip, at)
        return att[1] if att and att[0] == leaf else self.uplinks[leaf]


RAW_ACI = ROOT / "fixtures" / "raw-aci"

ACI_PREV_RAW = ROOT / "dist" / "phase8-raw-aci-prev"

RAW_NETWORKING = ROOT / "fixtures" / "raw-networking"


def write(name: str, events: list[dict], out_dir: Path = RAW) -> int:
    events = sorted(events, key=lambda e: e["time"])
    lines = [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in events]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_text("".join(line + "\n" for line in lines))
    return len(lines)
