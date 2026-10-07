#!/usr/bin/env python3
"""Generate TA-shaped synthetic HEC /event fixtures from a scenario file.

Default: fixtures/raw/scenario.json (NX-OS). --scenario aci: fixtures/raw-aci/scenario.json (ACI pilot).

Every event shape follows the installed TA or collector code cited next to its
builder. Field-level provenance and grounding gaps are listed in
fixtures/raw/FIELDS.md and fixtures/raw-aci/FIELDS.md. Output is deterministic.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "fixtures" / "raw"
NS = uuid.UUID("6f0b7c3e-6a63-4a43-9c55-2f4a0d1e7b10")

# Values the scenario does not define. Each is listed under "Scenario gaps" in FIELDS.md.
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
TCP_FLAGS_FULL_SESSION = 0x1B  # FIN|SYN|PSH|ACK, cumulative OR per vocabulary
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


# stream:netflow — field names: splunk_app_stream/default/streams/netflow:20-212,371;
# timestamp/endtime: Splunk_TA_stream_wire_data/default/props.conf:4-11, vocabularies/time.xml:20-24.
def stream_netflow(s: Scenario) -> list[dict]:
    out, late, seq = [], [], {}
    for conv in s.doc["conversations"]:
        exporters = [
            x.split(":", 1)[1] for x in conv["seen_by"] if x.startswith("netflow:")
        ]
        c_start, c_end = parse(conv["start"]), parse(conv["end"])
        proto = conv["transport"]
        for leaf in exporters:
            sw = s.switches[leaf]
            for src_ip, src_port, dst_ip, dst_port, leg_bytes in legs(conv):
                for start, end, share, is_late in segments(conv, c_start, c_end):
                    n_bytes = round(leg_bytes * share)
                    in_if = s.local_interface(leaf, src_ip, c_start)
                    out_if = s.local_interface(leaf, dst_ip, c_start)
                    seq[leaf] = seq.get(leaf, 1000) + 1
                    rel_start = int((start - EXPORTER_BOOT).total_seconds() * 1000)
                    rel_end = int((end - EXPORTER_BOOT).total_seconds() * 1000)
                    event = {
                        "endtime": iso_us(end),
                        "timestamp": iso_us(start),
                        "netflow_version": 9,
                        "seqnumber": seq[leaf],
                        "exporter_ip": sw["mgmt_ip"],
                        "exporter_sampling_interval": 1,
                        "exporter_uptime": rel_end + NETFLOW_INACTIVE_TIMEOUT_MS,
                        "src_ip": src_ip,
                        "dest_ip": dst_ip,
                        "src_port": src_port,
                        "dest_port": dst_port,
                        "protoid": PROTO_NUMBER[proto],
                        "tos": 0,
                        "bytes": n_bytes,
                        "packets": packets(n_bytes),
                        "tcp_flags": TCP_FLAGS_FULL_SESSION if proto == "tcp" else 0,
                        "flow_end_rel": rel_end,
                        "flow_start_rel": rel_start,
                        "input_snmpidx": s.ifindex[(leaf, in_if)],
                        "output_snmpidx": s.ifindex[(leaf, out_if)],
                        "version": 4,
                    }
                    if src_port is None:
                        # ICMP flows carry no L4 ports; the record has no port fields.
                        del event["src_port"], event["dest_port"]
                    (late if is_late else out).append(
                        envelope(
                            epoch(end),
                            STREAM_FORWARDER,
                            "stream:netflow",
                            "stream:netflow",
                            "netflow",
                            event,
                        )
                    )
    return out, late


def nd_vif(interface: str) -> str:
    return interface.replace("Ethernet", "eth")


# cisco:dc:nd:flows — writer bin/cisco_dc_nd_collector.py:191-213 (API entry + nd_host + fabricName,
# source=alert_type); fields default/props.conf:330-354 and data/models/Cisco_DCN_nexus_dashboard.json;
# "ts" is the API sort key at bin/cisco_dc_nd_collector.py:993.
def nd_flows(s: Scenario) -> list[dict]:
    nd = s.doc["nexus_dashboard"]
    out = []
    for conv in s.doc["conversations"]:
        if "nd" not in conv["seen_by"]:
            continue
        start, end = parse(conv["start"]), parse(conv["end"])
        for src_ip, src_port, dst_ip, dst_port, n_bytes in legs(conv):
            src_att, dst_att = s.attachment(src_ip, start), s.attachment(dst_ip, start)
            nodes, in_vif, out_vif = [], [], []
            if src_att:
                nodes.append(src_att[0])
                in_vif.append(nd_vif(src_att[1]))
            else:
                nodes.append("border-1")
            if dst_att:
                if dst_att[0] not in nodes:
                    nodes.append(dst_att[0])
                out_vif.append(nd_vif(dst_att[1]))
            elif "border-1" not in nodes:
                nodes.append("border-1")
            stats = {
                "nodeNames": nodes,
                "ingressVif": in_vif,
                "egressVif": out_vif,
                "ingressByteCount": n_bytes,
                "egressByteCount": n_bytes,
                "ingressPktCount": packets(n_bytes),
                "egressPktCount": packets(n_bytes),
                "dropPktCount": 0,
                "dropReasons": [],
            }
            mapped = "nd" in conv.get("ipv4_mapped_in", [])
            payload = {
                "flowId": str(stable_int(conv["id"], src_ip, src_port)),
                "ts": iso_ms(start),
                "srcIp": ipv4_mapped_full(src_ip) if mapped else src_ip,
                "dstIp": ipv4_mapped_full(dst_ip) if mapped else dst_ip,
                "srcPort": src_port,
                "dstPort": dst_port,
                "protocolName": conv["transport"].upper(),
                "stats": [stats],
                "nd_host": nd["host"],
                "fabricName": nd["fabric"],
            }
            collected = next_poll(end)
            out.append(
                envelope(
                    epoch(collected),
                    HEAVY_FORWARDER,
                    "flows",
                    "cisco:dc:nd:flows",
                    "cisco_dc",
                    json.dumps(payload, ensure_ascii=False),
                )
            )
    return out


# cisco:dc:nd:endpoints — writer bin/cisco_dc_nd_collector.py:252-272; fields default/props.conf:357-371
# (DATETIME_CONFIG=CURRENT) and Cisco_DCN_nexus_dashboard.json endpoints object (ip{}, displayInterface{}).
def nd_endpoints(s: Scenario) -> list[dict]:
    nd = s.doc["nexus_dashboard"]
    out = []

    def emit(payload: dict, at: datetime) -> None:
        out.append(
            envelope(
                epoch(next_poll(at)),
                HEAVY_FORWARDER,
                "endpoints",
                "cisco:dc:nd:endpoints",
                "cisco_dc",
                json.dumps(payload, ensure_ascii=False),
            )
        )

    for node in s.doc["kubernetes"]["nodes"]:
        mac = node.get("mac") or derived_mac(node["ip"])
        created = (
            parse(node["start"])
            if node.get("start")
            else min(parse(p["start"]) for p in s.pods if p["node"] == node["name"])
        )
        payload = {
            "endpointId": str(stable_int("nd-endpoint", node["ip"], mac)),
            "mac": mac,
            "ip": [node["ip"]],
            "nodeName": node["leaf"],
            "displayInterface": [nd_vif(node["interface"])],
            "modType": "creation",
            "createTime": iso_ms(created),
            "anomalyScore": 0,
            "nd_host": nd["host"],
        }
        emit(payload, created)
        if node.get("end"):
            # Incremental collection (bin/cisco_dc_nd_collector.py:757-800) reports the removal as a change.
            emit({**payload, "modType": "deletion"}, parse(node["end"]))
    for ep in s.doc["aci"]["endpoints"]:
        if not ep.get("nd_endpoint"):
            continue
        created = parse("2026-10-07T09:00:00Z")
        payload = {
            "endpointId": str(stable_int("nd-endpoint", ep["ip"], ep["mac"])),
            "mac": ep["mac"],
            "ip": [ep["ip"]],
            "nodeName": ep["leaf"],
            "displayInterface": [ep["interface"]],
            "vmName": ep["vm_name"],
            "tenant": ep["tenant"],
            "displayEpg": ep["epg"],
            "encap": ep["encap"],
            "modType": "creation",
            "createTime": iso_ms(created),
            "anomalyScore": 0,
            "nd_host": nd["host"],
        }
        emit(payload, created)
    return out


def aci_kv(key: str, value) -> str:
    # bin/cisco_nexus_aci.py:85-91 format_kv_pair
    value = str(value)
    if value.replace(".", "").isdigit():
        return f"{key}={value}"
    if value == "":
        return f'{key}=""'
    return f'{key}="{value}"'


def aci_event(
    at: datetime, attrs: list[tuple[str, object]], apic: str, component: str
) -> str:
    # bin/cisco_nexus_aci.py:729-751 (fvCEp) and :467-487 (other classes): tab-joined, header time first.
    parts = [naive_local(at)] + [aci_kv(k, v) for k, v in attrs]
    parts += [
        aci_kv("apic_host", apic),
        aci_kv("actual_host", apic),
        aci_kv("component", component),
    ]
    return "\t".join(parts)


def aci_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+00:00"


# cisco:dc:aci:stats / cisco:dc:aci:class — fvCEp branch bin/cisco_nexus_aci.py:619,694-751
# (children fvRsCEpToPathEp,fvIp for stats; fvIp only for class); class inputs default/inputs.conf:81,117;
# attribute names from data/models/Cisco_DCN_Systems.json classInfo fields; mac_addr extraction props.conf:232.
def aci(s: Scenario) -> tuple[list[dict], list[dict]]:
    a = s.doc["aci"]
    apic = a["apic_host"]
    stats, klass = [], []
    seen_from = s.window_start - timedelta(minutes=15)
    for ep in a["endpoints"]:
        mac, ip = ep["mac"], ep["ip"]
        cep = f"uni/tn-{ep['tenant']}/ap-{ep['app_profile']}/epg-{ep['epg']}/cep-{mac}"
        path = f"topology/pod-{ep['pod_id']}/paths-{ep['node_id']}/pathep-[{ep['interface']}]"
        vm_oid = f"vm-{ep['encap'].split('-')[-1]}"
        hv_oid = f"host-{ep['hypervisor'].split('-')[-1]}"
        vm_dn = f"{VMM_CONTROLLER}/vm-{vm_oid}"
        hv_dn = f"{VMM_CONTROLLER}/hv-{hv_oid}"
        mod_ts = aci_ts(datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc))
        cep_attrs = [
            ("dn", cep),
            ("encap", ep["encap"]),
            ("id", "0"),
            ("ip", ip),
            ("lcC", "learned,vmm"),
            ("lcOwn", "local"),
            ("mac", mac),
            ("mcastAddr", "not-applicable"),
            ("modTs", mod_ts),
            ("name", mac),
            ("status", ""),
            ("uid", "0"),
        ]
        path_child = [
            ("forceResolve", "yes"),
            ("lcC", "learned"),
            ("modTs", mod_ts),
            ("rType", "mo"),
            ("rn", f"rscEpToPathEp-[{path}]"),
            ("state", "formed"),
            ("stateQual", "none"),
            ("status", ""),
            ("tCl", "fabricPathEp"),
            ("tDn", path),
            ("tType", "mo"),
        ]
        ip_child = [("addr", ip)]
        for at in polls(seen_from, s.window_end):
            for source, sink, attrs in (
                (
                    "cisco_nexus_aci://stats",
                    (stats, "cisco:dc:aci:stats"),
                    cep_attrs + path_child + ip_child,
                ),
                (
                    "cisco_nexus_aci://classInfo_faultInst",
                    (klass, "cisco:dc:aci:class"),
                    cep_attrs + ip_child,
                ),
            ):
                rows, sourcetype = sink
                rows.append(
                    envelope(
                        epoch(at),
                        HEAVY_FORWARDER,
                        source,
                        sourcetype,
                        "cisco_dc",
                        aci_event(at, attrs, apic, "fvCEp"),
                    )
                )
            for component, attrs in (
                (
                    "fvRsVm",
                    [
                        ("dn", f"{cep}/rsvm"),
                        ("forceResolve", "yes"),
                        ("rType", "mo"),
                        ("state", "formed"),
                        ("status", ""),
                        ("tCl", "compVm"),
                        ("tDn", vm_dn),
                        ("tType", "mo"),
                    ],
                ),
                (
                    "compVm",
                    [
                        ("dn", vm_dn),
                        ("name", ep["vm_name"]),
                        ("oid", vm_oid),
                        ("state", "poweredOn"),
                        ("status", ""),
                    ],
                ),
                (
                    "fvRsHyper",
                    [
                        ("dn", f"{cep}/rshyper"),
                        ("forceResolve", "yes"),
                        ("rType", "mo"),
                        ("state", "formed"),
                        ("status", ""),
                        ("tCl", "compHv"),
                        ("tDn", hv_dn),
                        ("tType", "mo"),
                    ],
                ),
                (
                    "compHv",
                    [
                        ("dn", hv_dn),
                        ("name", ep["hypervisor"]),
                        ("oid", hv_oid),
                        ("state", "connected"),
                        ("status", ""),
                    ],
                ),
            ):
                klass.append(
                    envelope(
                        epoch(at),
                        HEAVY_FORWARDER,
                        "cisco_nexus_aci://classInfo_faultInst",
                        "cisco:dc:aci:class",
                        "cisco_dc",
                        aci_event(at, attrs, apic, component),
                    )
                )
    # topSystem is in classInfo_faultInst (default/inputs.conf:118); attributes from the
    # Cisco_DCN_Systems APIC_Inventory fields and the TA's own topSystem queries (macros.conf:43).
    leaves = sorted(
        {(ep["pod_id"], ep["node_id"], ep["leaf"]) for ep in a["endpoints"]}
    )
    for at in polls(seen_from, s.window_end):
        for pod_id, node_id, leaf in leaves:
            attrs = [
                ("address", f"10.0.72.{node_id % 256}"),
                ("dn", f"topology/pod-{pod_id}/node-{node_id}/sys"),
                ("fabricId", 1),
                ("fabricMAC", "00:22:BD:F8:19:FF"),
                ("id", node_id),
                ("inbMgmtAddr", "0.0.0.0"),
                ("modTs", "never"),
                ("mode", "unspecified"),
                ("name", leaf),
                ("oobMgmtAddr", f"192.0.2.{(node_id % 100) + 80}"),
                ("podId", pod_id),
                ("role", "leaf"),
                ("serial", f"FDO{stable_int(leaf, digits=5)}LF"),
                ("state", "in-service"),
                ("status", ""),
                ("systemUpTime", "45:02:11:09.000"),
            ]
            klass.append(
                envelope(
                    epoch(at),
                    HEAVY_FORWARDER,
                    "cisco_nexus_aci://classInfo_faultInst",
                    "cisco:dc:aci:class",
                    "cisco_dc",
                    aci_event(at, attrs, apic, "topSystem"),
                )
            )
    return stats, klass


def n9k_event(at: datetime, sw: dict, component: str, row) -> str:
    # bin/cisco_nexus_9k.py:445-473; TIMESTAMP_FORMAT bin/common/consts.py:12 (naive, so %z is empty).
    return json.dumps(
        {
            "timestamp": naive_local(at),
            "component": component,
            "device": f"{sw['mgmt_ip']}:443",
            "Row_info": row,
        },
        ensure_ascii=False,
    )


# cisco:dc:nexus9k — commands default/inputs.conf:136-183 ("show hostname", "show interface",
# "show cdp neighbors detail", "show version"); TABLE_/ROW_ splitting bin/cisco_nexus_9k.py:362-498;
# Row_info keys from the FIELDALIAS list at default/props.conf:15.
def nexus9k(s: Scenario) -> list[dict]:
    nd = s.doc["nexus_dashboard"]
    names = {i["device"]: [] for i in nd["interfaces"]}
    for i in nd["interfaces"]:
        names[i["device"]].append(i)
    cdp = []
    for n in nd["cdp_neighbors"]:
        cdp.append(n)
        cdp.append(
            {
                "device": n["neighbor"],
                "local_interface": n["neighbor_interface"],
                "neighbor": n["device"],
                "neighbor_interface": n["local_interface"],
            }
        )
    out = []
    for at in polls(s.window_start - timedelta(minutes=15), s.window_end):
        for name in sorted(s.switches):
            sw = s.switches[name]

            def emit(source: str, component: str, row) -> None:
                out.append(
                    envelope(
                        epoch(at),
                        HEAVY_FORWARDER,
                        source,
                        "cisco:dc:nexus9k",
                        "cisco_dc",
                        n9k_event(at, sw, component, row),
                    )
                )

            emit("cisco_nexus_9k://nxhostname", "nxhostname", [{"hostname": name}])
            # "show version" (default/inputs.conf:143); only nxos_ver_str is grounded (props.conf:21).
            emit(
                "cisco_nexus_9k://nxversion",
                "nxversion",
                [{"nxos_ver_str": sw["nxos"]}],
            )
            for i in names.get(name, []):
                emit(
                    "cisco_nexus_9k://nxinterface",
                    "nxinterface",
                    {
                        "interface": i["name"],
                        "state": "up",
                        "admin_state": "up",
                        "share_state": "Dedicated",
                        "desc": i["description"],
                        "eth_hw_desc": "100/1000/10000/25000 Ethernet",
                        "eth_hw_addr": derived_mac(sw["mgmt_ip"]).lower(),
                        "eth_bia_addr": derived_mac(sw["mgmt_ip"]).lower(),
                        "eth_mtu": "9216",
                        "eth_bw": 25000000,
                        "eth_duplex": "full",
                        "eth_speed": "25 Gb/s",
                        "medium": "broadcast",
                    },
                )
            for n in (c for c in cdp if c["device"] == name):
                peer = s.switches[n["neighbor"]]
                local_ifindex = s.ifindex.get((name, n["local_interface"]))
                row = {
                    "device_id": f"{peer['name']}({peer['serial']})",
                    "v4mgmtaddr": peer["mgmt_ip"],
                    "platform_id": peer["model"],
                    "capability": ["router", "switch", "Supports-STP-Dispute"],
                    "intf_id": n["local_interface"],
                    "port_id": n["neighbor_interface"],
                    "ttl": 150,
                }
                if local_ifindex is not None:
                    row = {"ifindex": local_ifindex, **row}
                emit("cisco_nexus_9k://nxneighbor", "nxneighbor", row)
    return out


# cisco:sfw:estreamer — writer bin/CiscoSecurityCloud/fw_estreamer/collect_events.py:150-163
# (FMC JSON + SourceHost, :153); field set bin/CiscoSecurityCloud/fw_estreamer/utils.py:103-116;
# names default/props.conf:985-1031 (TIME_PREFIX FirstPacketSecond :992); default index inputs.conf:49.
def ftd(s: Scenario) -> list[dict]:
    fw = s.doc["firewall"]
    out = []
    for conv in s.doc["conversations"]:
        if "ftd" not in conv["seen_by"]:
            continue
        c_ip, c_port = endpoint(conv["client"])
        s_ip, s_port = endpoint(conv["server"])
        inbound = conv["client"].startswith(
            tuple(e["ip"] + ":" for e in s.doc["external"])
        )
        ingress, egress = ("outside", "inside") if inbound else ("inside", "outside")
        first = int(parse(conv["start"]).timestamp())
        event = {
            "EventType": "ConnectionEvent",
            "FirstPacketSecond": first,
            "Device": fw["name"],
            "DeviceIP": fw["device_ip"],
            "ConnectionID": stable_int(conv["id"], digits=5),
            "InstanceID": 1,
            "InitiatorIP": c_ip,
            "InitiatorPort": c_port,
            "ResponderIP": s_ip,
            "ResponderPort": s_port,
            "Protocol": conv["transport"].upper(),
            "InitiatorBytes": conv["bytes_c2s"],
            "ResponderBytes": conv["bytes_s2c"],
            "InitiatorPackets": packets(conv["bytes_c2s"]),
            "ResponderPackets": packets(conv["bytes_s2c"]),
            "IngressInterface": ingress,
            "EgressInterface": egress,
            "IngressZone": fw["interfaces"][ingress]["zone"],
            "EgressZone": fw["interfaces"][egress]["zone"],
            "Application": "HTTPS" if s_port == 443 else "HTTP",
            "AC_RuleAction": "Allow",
            "SourceHost": FMC_HOST,
        }
        out.append(
            envelope(
                first,
                FMC_HOST,
                FTD_INPUT,
                "cisco:sfw:estreamer",
                "cisco_secure_fw",
                json.dumps(event),
            )
        )
    return out


def exec_id(node: str, pod: dict, binary: str) -> str:
    # Tetragon exec_id is base64("<node>:<ktime>:<pid>"); values are synthetic.
    ktime = stable_int(pod["uid"], binary, digits=15)
    pid = stable_int(pod["uid"], "pid", digits=5)
    return base64.b64encode(f"{node}:{ktime}:{pid}".encode()).decode()


# cisco:isovalent:processConnect — HEC input sourcetype cisco:isovalent (bin/CiscoSecurityCloud/isovalent/
# event_logger.py:35), rewritten at index time by default/transforms.conf:103-106 via props.conf:2303;
# field paths default/props.conf:2355-2378, process fields :2326-2353; default index inputs.conf:124.
def isovalent(s: Scenario) -> list[dict]:
    out = []
    for conv in s.doc["conversations"]:
        if "isovalent" not in conv["seen_by"]:
            continue
        c_ip, c_port = endpoint(conv["client"])
        s_ip, s_port = endpoint(conv["server"])
        at = parse(conv["start"])
        pod = s.pod_at(c_ip, at)
        workload = pod["service"] or pod["owner_name"].rsplit("-", 1)[0]
        binary = (
            "/usr/bin/nginx"
            if pod["namespace"] == "ingress-nginx"
            else f"/app/{workload}"
        )
        container = pod["service"] or workload.rsplit("-", 1)[-1]
        event = {
            "process_connect": {
                "process": {
                    "exec_id": exec_id(pod["node"], pod, binary),
                    "pid": stable_int(pod["uid"], "pid", digits=5),
                    "uid": 0,
                    "cwd": "/",
                    "binary": binary,
                    "arguments": "",
                    "pod": {
                        "namespace": pod["namespace"],
                        "name": pod["name"],
                        "container": {
                            "id": "containerd://" + stable_hex(pod["uid"], "container"),
                            "name": container,
                            "image": {
                                "id": "sha256:" + stable_hex(pod["uid"], "image"),
                                "name": f"registry.example/{pod['namespace']}/{container}:1.0.0",
                            },
                        },
                        "workload_kind": "Deployment",
                    },
                },
                "source_ip": c_ip,
                "source_port": c_port,
                "destination_ip": s_ip,
                "destination_port": s_port,
                "protocol": conv["transport"].upper(),
                "sock_cookie": str(stable_int(conv["id"], "sock", digits=15)),
            },
            "node_name": pod["node"],
            "time": iso_proto(at),
        }
        out.append(
            envelope(
                epoch(at),
                pod["node"],
                ISOVALENT_SOURCE,
                "cisco:isovalent",
                "cisco_isovalent",
                event,
            )
        )
    return out


def pod_object(
    s: Scenario, p: dict, phase: str, deleting: datetime | None = None
) -> dict:
    labels = {"pod-template-hash": p["pod_template_hash"]}
    if p.get("labels"):
        labels = dict(p["labels"])
    elif p["service"]:
        labels["app"] = p["service"]
    elif p["namespace"] == "ingress-nginx":
        labels["app.kubernetes.io/name"] = "ingress-nginx"
    else:
        labels["k8s-app"] = "kube-dns"
    container = p["service"] or p["owner_name"].rsplit("-", 1)[0].split("-")[-1]
    node = s.nodes[p["node"]]
    meta = {
        "name": p["name"],
        "namespace": p["namespace"],
        "uid": p["uid"],
        "creationTimestamp": iso_s(parse(p["start"])),
        "labels": labels,
        "ownerReferences": [
            {
                "apiVersion": "apps/v1",
                "kind": p["owner_kind"],
                "name": p["owner_name"],
                "uid": str(uuid.uuid5(NS, p["owner_name"])),
                "controller": True,
                "blockOwnerDeletion": True,
            }
        ],
    }
    if deleting:
        meta["deletionTimestamp"] = iso_s(deleting)
        meta["deletionGracePeriodSeconds"] = 30
    status = {"phase": phase, "hostIP": node["ip"], "hostIPs": [{"ip": node["ip"]}]}
    if phase != "Pending":
        status.update(
            {
                "podIP": p["ip"],
                "podIPs": [{"ip": p["ip"]}],
                "startTime": iso_s(parse(p["start"])),
            }
        )
    spec = {
        "nodeName": p["node"],
        "containers": [
            {
                "name": container,
                "image": f"registry.example/{p['namespace']}/{container}:1.0.0",
            }
        ],
    }
    if p.get("host_network"):
        # PodSpec.hostNetwork: the pod uses the node's network namespace, so podIP == hostIP.
        spec["hostNetwork"] = True
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta,
        "spec": spec,
        "status": status,
    }


# kube:object:pods (watch) — upstream k8sobjectsreceiver unstructured_to_logdata.go@v0.161.0
# (body {type, object}; attributes k8s.resource.name, event.domain, event.name; resource k8s.namespace.name);
# chart templates/config/_otel-k8s-cluster-receiver-config.tpl:209-224,247 (sourcetype, metric_source,
# k8s.cluster.name, host.name); HEC mapping pkg/translator/splunk logdata_to_splunk.go (observed time).
def kube_pods(s: Scenario) -> list[dict]:
    out = []

    def emit(at: datetime, p: dict, kind: str, obj: dict) -> None:
        fields = {
            "k8s.namespace.name": p["namespace"],
            "metric_source": "kubernetes",
            "k8s.cluster.name": s.cluster,
            "k8s.resource.name": "pods",
            "event.domain": "k8s",
            "event.name": p["name"],
        }
        if p.get("omit_cluster_field"):
            del fields["k8s.cluster.name"]
        out.append(
            envelope(
                epoch(at),
                CLUSTER_RECEIVER_NODE,
                "kubernetes",
                "kube:object:pods",
                "k8s",
                {"type": kind, "object": obj},
                fields,
            )
        )

    for p in s.pods:
        start = parse(p["start"])
        emit(start, p, "ADDED", pod_object(s, p, "Pending"))
        emit(start + timedelta(seconds=3), p, "MODIFIED", pod_object(s, p, "Running"))
        if p["end"]:
            end = parse(p["end"])
            grace = end - timedelta(seconds=30)
            emit(grace, p, "MODIFIED", pod_object(s, p, "Running", deleting=grace))
            emit(end, p, "DELETED", pod_object(s, p, "Running", deleting=grace))
    return out


# Spans — splunk_hec traces exporter pkg/translator/splunk traces_to_splunk.go@v0.161.0 (hecSpan field order,
# time = start seconds, resource attributes AsString as fields, host.name -> host); chart sourcetype from
# splunkPlatform.sourcetype (templates/config/_common.tpl:563) and source "kubernetes" (:563);
# k8s_attributes metadata templates/config/_common.tpl:195-215, label app -> k8s.pod.labels.app (values.yaml:320).
def otel_traces(s: Scenario) -> list[dict]:
    otel = s.doc["otel"]
    out = []
    for trace in s.doc["traces"]:
        for sp in trace["spans"]:
            start, end = parse(sp["start"]), parse(sp["end"])
            pod = next(
                p
                for p in s.pods
                if p["service"] == sp["service"] and s.pod_at(p["ip"], start) is p
            )
            event = {
                "trace_id": trace["trace_id"],
                "span_id": sp["span_id"],
                "parent_span_id": sp["parent"] or "",
                "name": sp["name"],
                "attributes": sp["attributes"],
                "end_time": epoch_ns(end),
                "kind": sp["kind"],
                "status": {"message": "", "code": "STATUS_CODE_UNSET"},
                "start_time": epoch_ns(start),
            }
            fields = {
                "service.name": sp["service"],
                "deployment.environment.name": s.env,
                "k8s.cluster.name": s.cluster,
                "k8s.namespace.name": pod["namespace"],
                "k8s.node.name": pod["node"],
                "k8s.pod.name": pod["name"],
                "k8s.pod.uid": pod["uid"],
                "k8s.pod.labels.app": pod["service"],
            }
            out.append(
                envelope(
                    epoch(start),
                    pod["node"],
                    "kubernetes",
                    otel["traces_sourcetype"],
                    "otel_traces",
                    event,
                    fields,
                )
            )
    return out


# ---------------------------------------------------------------------------
# ACI pilot scenario (fixtures/raw-aci/). Provenance per field: fixtures/raw-aci/FIELDS.md.
# ---------------------------------------------------------------------------

RAW_ACI = ROOT / "fixtures" / "raw-aci"
ACI_PROTO_NUMBER = {**PROTO_NUMBER, "ipip": 4}
# APIC l4:Port named constants (vzEntry dFromPort validValues, APIC MIM 6.1).
ACI_PORT_NAMES = {
    20: "ftpData",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    443: "https",
    554: "rtsp",
}
# Values the ACI scenario does not define; listed under "Scenario gaps" in FIELDS.md.
ACI_TOPOLOGY_INPUT = "cisco_nexus_aci://classInfo_adm"
ACI_MOD_TS = datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc)
ACI_UID = "15374"
HUBBLE_FILE_DELAY = timedelta(seconds=1)
RESERVED_IDENTITIES = {
    "reserved:world": 2,
    "reserved:remote-node": 6,
    "reserved:ingress": 8,
}


def nxos_ifindex(port: str) -> int:
    # NX-OS Ethernet ifIndex encoding 0x1A000000 + (port - 1) * 0x1000 for module 1 (assumed for ACI).
    module, num = port.removeprefix("eth").split("/")
    return 0x1A000000 + (int(module) - 1) * 0x80000 + (int(num) - 1) * 0x1000


def aci_port_value(port) -> str:
    if port == "unspecified":
        return "unspecified"
    return ACI_PORT_NAMES.get(int(port), str(port))


class AciScenario:
    def __init__(self, doc: dict):
        self.doc = doc
        self.window_start = parse(doc["window"]["start"])
        self.window_end = parse(doc["window"]["end"])
        f = doc["fabric"]
        self.fabric = f
        self.tenant, self.vrf = f["tenant"], f["vrf"]
        self.switches = {sw["name"]: sw for sw in f["switches"]}
        self.epgs = {f"{e['ap']}/{e['name']}": e for e in f["epgs"]}
        self.l3outs = {lo["name"]: lo for lo in f["l3outs"]}
        k8s = doc["kubernetes"]
        self.cluster = k8s["cluster"]
        self.nodes = {n["name"]: n for n in k8s["nodes"]}
        self.pods = k8s["pods"]
        self.pod_by_name = {p["name"]: p for p in self.pods}
        self.vms = {v["name"]: v for v in doc["vms"]}
        self.hypervisors = {h["name"]: h for h in doc["hypervisors"]}
        self.env = doc["otel"]["environment"]
        # Leaf access ports and how ACI classifies traffic entering them.
        self.ports = {}
        for n in k8s["nodes"]:
            if n["attachment"] == "epg":
                self.ports[(n["leaf"], n["interface"])] = ("epg", "k8s/nodes", n)
            else:
                self.ports[(n["leaf"], n["interface"])] = ("l3out", "k8s-bgp", n)
        for v in doc["vms"]:
            self.ports[(v["leaf"], v["interface"])] = (
                "epg",
                f"{v['ap']}/{v['epg']}",
                v,
            )
        for lo in f["l3outs"]:
            if lo.get("interface"):
                self.ports[(lo["leaves"][0], lo["interface"])] = (
                    "l3out",
                    lo["name"],
                    None,
                )

    def pod_at(self, ip: str, at: datetime) -> dict | None:
        for p in self.pods:
            end = parse(p["end"]) if p["end"] else None
            if p["ip"] == ip and parse(p["start"]) <= at and (end is None or at < end):
                return p
        return None

    def ext_epg(self, l3out: str, ip: str) -> str | None:
        best = None
        for epg in self.l3outs[l3out]["ext_epgs"]:
            for subnet in epg["subnets"]:
                net = ipaddress.ip_network(subnet)
                if ipaddress.ip_address(ip) in net and (
                    best is None or net.prefixlen > best[1]
                ):
                    best = (epg["name"], net.prefixlen)
        return best[0] if best else None

    def ingress_class(self, leaf: str, port: str, src_ip: str) -> str:
        """EPG or ExtEPG name ACI assigns to traffic entering a port (ingress classification)."""
        kind, name, _ = self.ports[(leaf, port)]
        if kind == "epg":
            return name.split("/")[1]
        return self.ext_epg(name, src_ip)

    def vlan(self, leaf: str, port: str) -> int:
        kind, name, _ = self.ports[(leaf, port)]
        encap = (
            self.epgs[name]["encap"]
            if kind == "epg"
            else self.l3outs[name].get("encap", "vlan-0")
        )
        return int(encap.split("-")[1])

    def sender_mac(self, leaf: str, port: str) -> str | None:
        _, _, owner = self.ports[(leaf, port)]
        return owner["mac"] if owner else None


def leg_endpoints(leg: dict) -> tuple[str, int | None, str, int | None]:
    s_ip, s_port = endpoint(leg["src"])
    d_ip, d_port = endpoint(leg["dst"])
    return s_ip, s_port, d_ip, d_port


def split_at(spec: str) -> tuple[str, str]:
    leaf, port = spec.split(":", 1)
    return leaf, port


# stream:netflow from ACI leaves — Stream field names as in stream_netflow(); ACI NetFlow v9 record
# policy (APIC MIM netflow:RecordPol collect/match) exports bytes, packets, src-intf, tcp-flags,
# ts-first, ts-recent with match keys src/dst IP, ports, proto, vlan, mac, tos — so no output_snmpidx.
# ingress_vlan/src_mac/dest_mac: splunk_app_stream/default/streams/netflow:119,126,356.
def aci_netflow(s: AciScenario) -> list[dict]:
    out, seq = [], {}
    router_mac = s.fabric["router_mac"]
    for conv in s.doc["conversations"]:
        start, end = parse(conv["start"]), parse(conv["end"])
        for leg in conv["wire"]:
            if leg.get("netflow") is False:
                continue
            leaf, port = split_at(leg["ingress"])
            sw = s.switches[leaf]
            s_ip, s_port, d_ip, d_port = leg_endpoints(leg)
            seq[leaf] = seq.get(leaf, 2000) + 1
            rel_start = int((start - EXPORTER_BOOT).total_seconds() * 1000)
            rel_end = int((end - EXPORTER_BOOT).total_seconds() * 1000)
            proto = leg["proto"]
            event = {
                "endtime": iso_us(end),
                "timestamp": iso_us(start),
                "netflow_version": 9,
                "seqnumber": seq[leaf],
                "exporter_ip": sw["oob"],
                "exporter_uptime": rel_end + NETFLOW_INACTIVE_TIMEOUT_MS,
                "src_ip": s_ip,
                "dest_ip": d_ip,
                "src_port": s_port,
                "dest_port": d_port,
                "protoid": ACI_PROTO_NUMBER[proto],
                "tos": 0,
                "bytes": leg["bytes"],
                "packets": packets(leg["bytes"]),
                "tcp_flags": TCP_FLAGS_FULL_SESSION if proto == "tcp" else 0,
                "flow_end_rel": rel_end,
                "flow_start_rel": rel_start,
                "input_snmpidx": nxos_ifindex(port),
                "ingress_vlan": s.vlan(leaf, port),
                "version": 4,
            }
            mac = s.sender_mac(leaf, port)
            if mac:
                event["src_mac"] = mac
                event["dest_mac"] = router_mac
            if s_port is None:
                del event["src_port"], event["dest_port"]
            out.append(
                envelope(
                    epoch(end),
                    STREAM_FORWARDER,
                    "stream:netflow",
                    "stream:netflow",
                    "netflow",
                    event,
                )
            )
    return out


# cisco:dc:nd:flows for the ACI site — writer bin/cisco_dc_nd_collector.py:191-213; ACI fields
# ingressTenant/ingressVrf/srcEpg from data/models/Cisco_DCN_nexus_dashboard.json (flows object).
def aci_nd_flows(s: AciScenario) -> list[dict]:
    nd = s.doc["nexus_dashboard"]
    out = []
    for conv in s.doc["conversations"]:
        start, end = parse(conv["start"]), parse(conv["end"])
        for leg in conv["wire"]:
            if not leg.get("nd"):
                continue
            in_leaf, in_port = split_at(leg["ingress"])
            out_leaf, out_port = split_at(leg["egress"])
            s_ip, s_port, d_ip, d_port = leg_endpoints(leg)
            nodes = [in_leaf] + ([out_leaf] if out_leaf != in_leaf else [])
            stats = {
                "nodeNames": nodes,
                "ingressVif": [in_port],
                "egressVif": [out_port],
                "ingressByteCount": leg["bytes"],
                "egressByteCount": leg["bytes"],
                "ingressPktCount": packets(leg["bytes"]),
                "egressPktCount": packets(leg["bytes"]),
                "dropPktCount": 0,
                "dropReasons": [],
            }
            payload = {
                "flowId": str(stable_int(conv["id"], s_ip, s_port)),
                "ts": iso_ms(start),
                "srcIp": s_ip,
                "dstIp": d_ip,
                "srcPort": s_port,
                "dstPort": d_port,
                "protocolName": conv["transport"].upper(),
                "ingressTenant": s.tenant,
                "ingressVrf": s.vrf,
                "srcEpg": s.ingress_class(in_leaf, in_port, s_ip),
                "stats": [stats],
                "nd_host": nd["host"],
                "fabricName": nd["fabric"],
            }
            out.append(
                envelope(
                    epoch(next_poll(end)),
                    HEAVY_FORWARDER,
                    "flows",
                    "cisco:dc:nd:flows",
                    "cisco_dc",
                    json.dumps(payload, ensure_ascii=False),
                )
            )
    return out


# cisco:dc:nd:endpoints — same writer and fields as nd_endpoints(); displayBd per the TA data model.
def aci_nd_endpoints(s: AciScenario) -> list[dict]:
    nd = s.doc["nexus_dashboard"]
    created = parse("2026-10-07T09:00:00Z")
    out = []
    owners = [
        (
            v["ip"],
            v["mac"],
            v["leaf"],
            v["interface"],
            f"{v['ap']}/{v['epg']}",
            v["name"],
        )
        for v in s.doc["vms"]
        if v.get("nd_endpoint")
    ] + [
        (n["ip"], n["mac"], n["leaf"], n["interface"], "k8s/nodes", None)
        for n in s.doc["kubernetes"]["nodes"]
        if n["attachment"] == "epg"
    ]
    for ip, mac, leaf, port, epg_key, vm_name in owners:
        epg = s.epgs[epg_key]
        payload = {
            "endpointId": str(stable_int("nd-endpoint", ip, mac)),
            "mac": mac,
            "ip": [ip],
            "nodeName": leaf,
            "displayInterface": [port],
            "tenant": s.tenant,
            "displayBd": epg["bd"],
            "displayEpg": epg["name"],
            "encap": epg["encap"],
            "modType": "creation",
            "createTime": iso_ms(created),
            "anomalyScore": 0,
            "nd_host": nd["host"],
        }
        if vm_name:
            payload["vmName"] = vm_name
        out.append(
            envelope(
                epoch(next_poll(created)),
                HEAVY_FORWARDER,
                "endpoints",
                "cisco:dc:nd:endpoints",
                "cisco_dc",
                json.dumps(payload, ensure_ascii=False),
            )
        )
    return out


def rel_attrs(dn: str, t_cl: str, t_dn: str, extra=()) -> list[tuple[str, object]]:
    # fvRsVm/fvRsHyper/fvRsCEpToPathEp attribute set as in aci().
    return sorted(
        [
            ("dn", dn),
            ("forceResolve", "yes"),
            ("rType", "mo"),
            ("state", "formed"),
            ("status", ""),
            ("tCl", t_cl),
            ("tDn", t_dn),
            ("tType", "mo"),
            *extra,
        ]
    )


def lldp_attrs(
    local_dn: str,
    sys_name: str,
    sys_desc: str,
    port_desc: str,
    mgmt_ip: str,
    chassis_mac: str,
    port_mac: str,
    capability: str,
    mon_pol: str,
) -> list[tuple[str, object]]:
    # lldp:AdjEp attributes in APIC order (real sample: DataDog cisco_aci fixtures, fabric lldpAdjEp).
    return [
        ("capability", capability),
        ("chassisIdT", "mac"),
        ("chassisIdV", chassis_mac.lower()),
        ("childAction", ""),
        ("dn", local_dn),
        ("enCap", ""),
        ("id", 1),
        ("mgmtId", 0),
        ("mgmtIp", mgmt_ip),
        ("mgmtPortMac", "unspecified"),
        ("modTs", aci_ts(ACI_MOD_TS)),
        ("monPolDn", mon_pol),
        ("name", ""),
        ("portDesc", port_desc),
        ("portIdT", "mac"),
        ("portIdV", port_mac.lower()),
        ("portVlan", "unspecified"),
        ("stQual", ""),
        ("status", ""),
        ("sysDesc", sys_desc),
        ("sysName", sys_name),
        ("ttl", 120),
    ]


def policy_common(dn: str, name: str) -> list[tuple[str, object]]:
    return [
        ("annotation", ""),
        ("childAction", ""),
        ("dn", dn),
        ("extMngdBy", ""),
        ("lcOwn", "local"),
        ("modTs", aci_ts(ACI_MOD_TS)),
        ("monPolDn", "uni/tn-common/monepg-default"),
        ("name", name),
        ("nameAlias", ""),
        ("status", ""),
        ("uid", ACI_UID),
        ("userdom", ":all:"),
    ]


def class_dn(s: AciScenario, ref: dict) -> str:
    if "epg" in ref:
        ap, epg = ref["epg"].split("/")
        return f"uni/tn-{s.tenant}/ap-{ap}/epg-{epg}"
    l3out, instp = ref["instp"].split("/")
    return f"uni/tn-{s.tenant}/out-{l3out}/instP-{instp}"


def contract_objects(s: AciScenario) -> list[tuple[str, list]]:
    """(component, attrs) for vzBrCP, vzSubj, vzRsSubjFiltAtt, vzEntry, fvRsCons, fvRsProv,
    l3extInstP and l3extSubnet; attribute names from the APIC MIM 6.1 class definitions."""
    t = s.tenant
    objs = []
    for c in s.fabric["contracts"]:
        brc = f"uni/tn-{t}/brc-{c['name']}"
        objs.append(
            (
                "vzBrCP",
                sorted(
                    policy_common(brc, c["name"])
                    + [
                        ("configIssues", ""),
                        ("descr", ""),
                        ("intent", "install"),
                        ("ownerKey", ""),
                        ("ownerTag", ""),
                        ("prio", "unspecified"),
                        ("reevaluateAll", "no"),
                        ("scope", "context"),
                        ("targetDscp", "unspecified"),
                    ]
                ),
            )
        )
        for subj in c["subjects"]:
            sdn = f"{brc}/subj-{subj['name']}"
            objs.append(
                (
                    "vzSubj",
                    sorted(
                        policy_common(sdn, subj["name"])
                        + [
                            ("accessPrivilege", "USE"),
                            ("configIssues", ""),
                            ("consMatchT", "AtleastOne"),
                            ("descr", ""),
                            ("prio", "unspecified"),
                            ("provMatchT", "AtleastOne"),
                            ("revFltPorts", "yes"),
                            ("targetDscp", "unspecified"),
                        ]
                    ),
                )
            )
            for flt in subj["filters"]:
                fdn = f"uni/tn-{t}/flt-{flt['name']}"
                objs.append(
                    (
                        "vzRsSubjFiltAtt",
                        sorted(
                            [
                                (k, v)
                                for k, v in policy_common(
                                    f"{sdn}/rssubjFiltAtt-{flt['name']}", ""
                                )
                                if k not in ("name", "nameAlias")
                            ]
                            + [
                                ("accessPrivilege", "USE"),
                                ("action", flt["action"]),
                                (
                                    "directives",
                                    ""
                                    if flt["directives"] == "none"
                                    else flt["directives"],
                                ),
                                ("forceResolve", "yes"),
                                ("priorityOverride", "default"),
                                ("rType", "mo"),
                                ("state", "formed"),
                                ("stateQual", "none"),
                                ("tCl", "vzFilter"),
                                ("tContextDn", ""),
                                ("tDn", fdn),
                                ("tRn", f"flt-{flt['name']}"),
                                ("tType", "name"),
                                ("tnVzFilterName", flt["name"]),
                            ]
                        ),
                    )
                )
                for e in flt["entries"]:
                    objs.append(
                        (
                            "vzEntry",
                            sorted(
                                policy_common(f"{fdn}/e-{e['name']}", e["name"])
                                + [
                                    ("applyToFrag", "no"),
                                    ("arpOpc", "unspecified"),
                                    ("dFromPort", aci_port_value(e["d_from"])),
                                    ("dToPort", aci_port_value(e["d_to"])),
                                    ("descr", ""),
                                    ("etherT", e.get("ether_t", "ip")),
                                    ("icmpv4T", "unspecified"),
                                    ("icmpv6T", "unspecified"),
                                    ("matchDscp", "unspecified"),
                                    ("prot", e["prot"]),
                                    ("sFromPort", "unspecified"),
                                    ("sToPort", "unspecified"),
                                    ("stateful", "no"),
                                    ("tcpRules", ""),
                                ]
                            ),
                        )
                    )
        for side, refs, rn in (
            ("fvRsCons", c["consumers"], "rscons"),
            ("fvRsProv", c["providers"], "rsprov"),
        ):
            for ref in refs:
                extra = (
                    [("deplInfo", "")]
                    if side == "fvRsCons"
                    else [("matchT", "AtleastOne")]
                )
                objs.append(
                    (
                        side,
                        sorted(
                            [
                                (k, v)
                                for k, v in policy_common(
                                    f"{class_dn(s, ref)}/{rn}-{c['name']}", ""
                                )
                                if k not in ("name", "nameAlias")
                            ]
                            + extra
                            + [
                                ("ctrctUpd", "ctrct"),
                                ("forceResolve", "yes"),
                                ("intent", "install"),
                                ("prio", "unspecified"),
                                ("rType", "mo"),
                                ("state", "formed"),
                                ("stateQual", "none"),
                                ("tCl", "vzBrCP"),
                                ("tContextDn", ""),
                                ("tDn", brc),
                                ("tRn", f"brc-{c['name']}"),
                                ("tType", "name"),
                                ("tnVzBrCPName", c["name"]),
                                ("triggerSt", "triggerable"),
                                ("updateCollection", "no"),
                            ]
                        ),
                    )
                )
    for lo in s.fabric["l3outs"]:
        for epg in lo["ext_epgs"]:
            idn = f"uni/tn-{t}/out-{lo['name']}/instP-{epg['name']}"
            objs.append(
                (
                    "l3extInstP",
                    sorted(
                        policy_common(idn, epg["name"])
                        + [
                            ("configIssues", ""),
                            ("configSt", "applied"),
                            ("descr", ""),
                            ("exceptionTag", ""),
                            ("floodOnEncap", "disabled"),
                            ("isSharedSrvMsiteEPg", "no"),
                            ("matchT", "AtleastOne"),
                            ("pcEnfPref", "unenforced"),
                            ("pcTag", epg["pc_tag"]),
                            ("pcTagAllocSrc", "idmanager"),
                            ("prefGrMemb", "exclude"),
                            ("prio", "unspecified"),
                            ("scope", s.fabric["vrf_vnid"]),
                            ("targetDscp", "unspecified"),
                            ("triggerSt", "triggerable"),
                            ("txId", 0),
                        ]
                    ),
                )
            )
            for subnet in epg["subnets"]:
                objs.append(
                    (
                        "l3extSubnet",
                        sorted(
                            policy_common(f"{idn}/extsubnet-[{subnet}]", "")
                            + [
                                ("aggregate", ""),
                                ("descr", ""),
                                ("ip", subnet),
                                ("scope", "import-security"),
                            ]
                        ),
                    )
                )
    return objs


# ACI collections — writers bin/cisco_nexus_aci.py:467-490 (classInfo, any class) and :619,694-751
# (fvCEp). Inputs: stats default/inputs.conf:81; classInfo_faultInst :117 (fvCEp, topSystem, compVm,
# compHv, fvRsVm, fvRsHyper, fvRsCons, fvRsProv); classInfo_fvRsCEpToPathEp :111 (acllog*); the
# admin-added classInfo input ACI_TOPOLOGY_INPUT (fabricLink, lldpAdjEp, contracts, l3extInstP/Subnet).
def aci_collections(s: AciScenario) -> tuple[list[dict], list[dict]]:
    f = s.fabric
    apic = f["apic"]["oob"]
    pod_id = f["pod_id"]
    stats, klass = [], []
    seen_from = s.window_start - timedelta(minutes=15)
    mod_ts = aci_ts(ACI_MOD_TS)
    sw_by_name = s.switches

    def emit(rows, source, sourcetype, at, attrs, component):
        rows.append(
            envelope(
                epoch(at),
                HEAVY_FORWARDER,
                source,
                sourcetype,
                "cisco_dc",
                aci_event(at, attrs, apic, component),
            )
        )

    endpoints = []
    for v in s.doc["vms"]:
        endpoints.append((v, f"{v['ap']}/{v['epg']}", True))
    for n in s.doc["kubernetes"]["nodes"]:
        if n["attachment"] == "epg":
            endpoints.append((n, "k8s/nodes", False))
    for at in polls(seen_from, s.window_end):
        for owner, epg_key, is_vm in endpoints:
            epg = s.epgs[epg_key]
            ap, epg_name = epg_key.split("/")
            mac, ip = owner["mac"], owner["ip"]
            node_id = sw_by_name[owner["leaf"]]["node_id"]
            cep = f"uni/tn-{s.tenant}/ap-{ap}/epg-{epg_name}/cep-{mac}"
            path = (
                f"topology/pod-{pod_id}/paths-{node_id}/pathep-[{owner['interface']}]"
            )
            cep_attrs = [
                ("dn", cep),
                ("encap", epg["encap"]),
                ("id", "0"),
                ("ip", ip),
                ("lcC", "learned,vmm" if is_vm else "learned"),
                ("lcOwn", "local"),
                ("mac", mac),
                ("mcastAddr", "not-applicable"),
                ("modTs", mod_ts),
                ("name", mac),
                ("status", ""),
                ("uid", "0"),
            ]
            path_child = [
                ("forceResolve", "yes"),
                ("lcC", "learned"),
                ("modTs", mod_ts),
                ("rType", "mo"),
                ("rn", f"rscEpToPathEp-[{path}]"),
                ("state", "formed"),
                ("stateQual", "none"),
                ("status", ""),
                ("tCl", "fabricPathEp"),
                ("tDn", path),
                ("tType", "mo"),
            ]
            ip_child = [("addr", ip)]
            emit(
                stats,
                "cisco_nexus_aci://stats",
                "cisco:dc:aci:stats",
                at,
                cep_attrs + path_child + ip_child,
                "fvCEp",
            )
            emit(
                klass,
                "cisco_nexus_aci://classInfo_faultInst",
                "cisco:dc:aci:class",
                at,
                cep_attrs + ip_child,
                "fvCEp",
            )
            if not is_vm:
                continue
            vm_oid = f"vm-{epg['encap'].split('-')[-1]}"
            hv_oid = f"host-{owner['hypervisor'].split('-')[-1]}"
            vm_dn = f"{VMM_CONTROLLER}/vm-{vm_oid}"
            hv_dn = f"{VMM_CONTROLLER}/hv-{hv_oid}"
            for component, attrs in (
                ("fvRsVm", rel_attrs(f"{cep}/rsvm", "compVm", vm_dn)),
                (
                    "compVm",
                    [
                        ("cfgdOs", owner["os"]),
                        ("dn", vm_dn),
                        ("name", owner["name"]),
                        ("oid", vm_oid),
                        ("os", owner["os"]),
                        ("state", "poweredOn"),
                        ("status", ""),
                        ("type", "virt"),
                    ],
                ),
                ("fvRsHyper", rel_attrs(f"{cep}/rshyper", "compHv", hv_dn)),
                (
                    "compHv",
                    [
                        ("dn", hv_dn),
                        ("name", owner["hypervisor"]),
                        ("oid", hv_oid),
                        ("state", "connected"),
                        ("status", ""),
                    ],
                ),
            ):
                emit(
                    klass,
                    "cisco_nexus_aci://classInfo_faultInst",
                    "cisco:dc:aci:class",
                    at,
                    attrs,
                    component,
                )
        # topSystem for leaves, spines and the controller (same attribute set as aci()).
        systems = [
            (sw["node_id"], sw["name"], sw["role"], sw["tep"], sw["oob"], sw["serial"])
            for sw in f["switches"]
        ] + [
            (
                f["apic"]["node_id"],
                f["apic"]["name"],
                "controller",
                f["apic"]["tep"],
                f["apic"]["oob"],
                "FCH2024V1AP",
            )
        ]
        for node_id, name, role, tep, oob, serial in systems:
            attrs = [
                ("address", tep),
                ("dn", f"topology/pod-{pod_id}/node-{node_id}/sys"),
                ("fabricId", 1),
                ("fabricMAC", f["router_mac"]),
                ("id", node_id),
                ("inbMgmtAddr", "0.0.0.0"),
                ("modTs", "never"),
                ("mode", "unspecified"),
                ("name", name),
                ("oobMgmtAddr", oob),
                ("podId", pod_id),
                ("role", role),
                ("serial", serial),
                ("state", "in-service"),
                ("status", ""),
                ("systemUpTime", "45:02:11:09.000"),
            ]
            emit(
                klass,
                "cisco_nexus_aci://classInfo_faultInst",
                "cisco:dc:aci:class",
                at,
                attrs,
                "topSystem",
            )
        # fabricLink — DN topology/pod-{id}/lnkcnt-{n}/lnk-{n1}-{s1}-{p1}-to-{n2}-{s2}-{p2} (MIM).
        for link in f["fabric_links"]:
            leaf, spine = sw_by_name[link["leaf"]], sw_by_name[link["spine"]]
            s1, p1 = link["leaf_port"].removeprefix("eth").split("/")
            s2, p2 = link["spine_port"].removeprefix("eth").split("/")
            n1, n2 = leaf["node_id"], spine["node_id"]
            attrs = [
                ("childAction", ""),
                (
                    "dn",
                    f"topology/pod-{pod_id}/lnkcnt-{n2}/lnk-{n1}-{s1}-{p1}-to-{n2}-{s2}-{p2}",
                ),
                ("lcOwn", "local"),
                ("linkDescr", ""),
                ("linkState", "ok"),
                ("modTs", mod_ts),
                ("monPolDn", "uni/fabric/monfab-default"),
                ("n1", n1),
                ("n2", n2),
                ("p1", p1),
                ("p2", p2),
                ("r1", "leaf"),
                ("r2", "spine"),
                ("s1", s1),
                ("s2", s2),
                ("sp1", 0),
                ("sp2", 0),
                ("status", ""),
                ("wiringIssues", ""),
            ]
            emit(
                klass, ACI_TOPOLOGY_INPUT, "cisco:dc:aci:class", at, attrs, "fabricLink"
            )
        # lldpAdjEp — fabric uplinks seen from both ends, plus host ports (Kubernetes nodes, ESXi).
        for link in f["fabric_links"]:
            leaf, spine = sw_by_name[link["leaf"]], sw_by_name[link["spine"]]
            for local, local_port, peer, peer_port in (
                (leaf, link["leaf_port"], spine, link["spine_port"]),
                (spine, link["spine_port"], leaf, link["leaf_port"]),
            ):
                peer_mac = derived_mac(peer["tep"])
                attrs = lldp_attrs(
                    f"topology/pod-{pod_id}/node-{local['node_id']}/sys/lldp/inst/if-[{local_port}]/adj-1",
                    peer["name"],
                    f"topology/pod-{pod_id}/node-{peer['node_id']}",
                    f"topology/pod-{pod_id}/paths-{peer['node_id']}/pathep-[{peer_port}]",
                    peer["tep"],
                    peer_mac,
                    peer_mac,
                    "router",
                    "uni/fabric/monfab-default",
                )
                emit(
                    klass,
                    ACI_TOPOLOGY_INPUT,
                    "cisco:dc:aci:class",
                    at,
                    attrs,
                    "lldpAdjEp",
                )
        hosts = [
            (
                n["leaf"],
                n["interface"],
                n["name"],
                n["ip"],
                n["mac"],
                n["host_nic"],
                "Ubuntu 24.04.1 LTS Linux 6.8.0-45-generic #45-Ubuntu SMP x86_64",
                "bridge,router",
            )
            for n in s.doc["kubernetes"]["nodes"]
        ] + [
            (
                h["leaf"],
                h["interface"],
                h["name"],
                "0.0.0.0",
                h["mac"],
                "vmnic2",
                "VMware ESX Releasebuild-24280767",
                "bridge",
            )
            for h in s.doc["hypervisors"]
        ]
        for leaf_name, port, sys_name, mgmt_ip, mac, nic, desc, cap in hosts:
            leaf = sw_by_name[leaf_name]
            attrs = lldp_attrs(
                f"topology/pod-{pod_id}/node-{leaf['node_id']}/sys/lldp/inst/if-[{port}]/adj-1",
                sys_name,
                desc,
                nic,
                mgmt_ip,
                mac,
                mac,
                cap,
                "uni/infra/moninfra-default",
            )
            emit(
                klass, ACI_TOPOLOGY_INPUT, "cisco:dc:aci:class", at, attrs, "lldpAdjEp"
            )
        for component, attrs in contract_objects(s):
            source = (
                "cisco_nexus_aci://classInfo_faultInst"
                if component in ("fvRsCons", "fvRsProv")
                else ACI_TOPOLOGY_INPUT
            )
            emit(klass, source, "cisco:dc:aci:class", at, attrs, component)
    # ACL-log records (acllog:PermitL3Pkt / acllog:DropL3Pkt), collected on the poll after the packet.
    router_mac = f["router_mac"]
    record = 0
    for conv in s.doc["conversations"]:
        for acl in conv.get("acl", []):
            record += 1
            leaf = sw_by_name[acl["leaf"]]
            s_ip, s_port = endpoint(acl["src"])
            d_ip, d_port = endpoint(acl["dst"])
            at = parse(acl["time"])
            cls = conv["aci_class"]
            src_kind, src_ref = cls["client"].split(":", 1)
            dst_kind, dst_ref = cls["server"].split(":", 1)
            src_epg_dn = class_dn(s, {src_kind: src_ref})
            dst_epg_dn = class_dn(s, {dst_kind: dst_ref})
            src_vm = next(v for v in s.doc["vms"] if v["ip"] == s_ip)
            src_mac = src_vm["mac"]
            ts = aci_ts(at)
            component = (
                "acllogPermitL3Pkt" if acl["action"] == "permit" else "acllogDropL3Pkt"
            )
            rn_prefix = "permitl3pkt" if acl["action"] == "permit" else "dropl3pkt"
            pc = lambda kind, ref: (  # noqa: E731
                s.epgs[ref]["pc_tag"]
                if kind == "epg"
                else next(
                    e["pc_tag"]
                    for e in s.l3outs[ref.split("/")[0]]["ext_epgs"]
                    if e["name"] == ref.split("/")[1]
                )
            )
            attrs = [
                ("childAction", ""),
                (
                    "dn",
                    f"topology/pod-{pod_id}/node-{leaf['node_id']}/ndbgs/acllog/tn-{s.tenant}/ctx-{s.vrf}/"
                    f"{rn_prefix}-{record}-smac-{src_mac}-dmac-{router_mac}-time-{ts}",
                ),
                ("dstEpgName", dst_epg_dn),
                ("dstIp", d_ip),
                ("dstMacAddr", router_mac),
                ("dstPcTag", pc(dst_kind, dst_ref)),
                ("dstPort", d_port),
                ("lcOwn", "local"),
                ("modTs", ts),
                ("pktLen", 60),
                ("protocol", conv["transport"]),
                ("recordId", record),
                ("srcEpgName", src_epg_dn),
                ("srcIntf", src_vm["interface"]),
                ("srcIp", s_ip),
                ("srcMacAddr", src_mac),
                ("srcPcTag", pc(src_kind, src_ref)),
                ("srcPort", s_port),
                ("status", ""),
                ("timeStamp", ts),
                ("vrfEncap", f"vxlan-{f['vrf_vnid']}"),
            ]
            emit(
                klass,
                "cisco_nexus_aci://classInfo_fvRsCEpToPathEp",
                "cisco:dc:aci:class",
                next_poll(at),
                attrs,
                component,
            )
    return stats, klass


def k8s_meta(
    name: str, uid: str, created: str, namespace: str | None = None, **extra
) -> dict:
    meta = {"name": name}
    if namespace:
        meta["namespace"] = namespace
    meta.update(
        {
            "uid": uid,
            "resourceVersion": str(stable_int(uid, digits=7)),
            "creationTimestamp": created,
        }
    )
    meta.update({k: v for k, v in extra.items() if v})
    return meta


def service_object(s: AciScenario, svc: dict, with_status: bool) -> dict:
    owner = svc.get("owner")
    owner_refs = None
    if owner:
        # Cilium sets the Gateway owner reference with gateway v1beta1
        # (operator/pkg/model/translation/gateway-api/translator.go:172).
        api = (
            "gateway.networking.k8s.io/v1beta1"
            if owner["kind"] == "Gateway"
            else "networking.k8s.io/v1"
        )
        kind_key = "gateway" if owner["kind"] == "Gateway" else "ingress"
        owner_refs = [
            {
                "apiVersion": api,
                "kind": owner["kind"],
                "name": owner["name"],
                "uid": str(
                    uuid.uuid5(
                        NS, f"aci-pilot/{kind_key}/{svc['namespace']}/{owner['name']}"
                    )
                ),
                "controller": True,
            }
        ]
    spec = {
        "type": svc["type"],
        "clusterIP": svc["cluster_ip"],
        "clusterIPs": [svc["cluster_ip"]],
        "ipFamilies": ["IPv4"],
        "ipFamilyPolicy": "SingleStack",
        "ports": [],
        "sessionAffinity": "None",
        "internalTrafficPolicy": "Cluster",
    }
    for p in svc["ports"]:
        port = {
            "name": p["name"],
            "port": p["port"],
            "protocol": p["protocol"],
            "targetPort": p["target_port"],
        }
        if svc["type"] in ("NodePort", "LoadBalancer") and p.get("node_port"):
            port["nodePort"] = p["node_port"]
        spec["ports"].append(port)
    if svc.get("selector"):
        spec["selector"] = svc["selector"]
    if svc["type"] in ("NodePort", "LoadBalancer"):
        spec["externalTrafficPolicy"] = svc["external_traffic_policy"]
    if svc["type"] == "LoadBalancer":
        spec["allocateLoadBalancerNodePorts"] = True
        if svc["external_traffic_policy"] == "Local":
            spec["healthCheckNodePort"] = 32000 + stable_int(svc["name"], digits=3)
    status = {"loadBalancer": {}}
    if svc["type"] == "LoadBalancer" and with_status:
        status = {
            "loadBalancer": {
                "ingress": [{"ip": svc["load_balancer_ip"], "ipMode": "VIP"}]
            }
        }
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": k8s_meta(
            svc["name"],
            svc["uid"],
            "2026-10-07T09:00:00Z",
            svc["namespace"],
            labels=svc.get("labels"),
            annotations=svc.get("annotations"),
            ownerReferences=owner_refs,
        ),
        "spec": spec,
        "status": status,
    }


def endpointslice_objects(s: AciScenario) -> list[dict]:
    out = []
    for svc in s.doc["kubernetes"]["services"]:
        name = f"{svc['name']}-{stable_hex(svc['uid'], length=5)}"
        uid = str(uuid.uuid5(NS, f"aci-pilot/eps/{svc['namespace']}/{svc['name']}"))
        svc_ref = [
            {
                "apiVersion": "v1",
                "kind": "Service",
                "name": svc["name"],
                "uid": svc["uid"],
                "controller": True,
                "blockOwnerDeletion": True,
            }
        ]
        if not svc.get("selector"):
            # Cilium Gateway/Ingress services: dummy endpoint 192.192.192.192:9999
            # (operator/pkg/model/translation/gateway-api/translator.go:384-424, ingress/dedicated_ingress.go:159-197).
            owner = svc["owner"]
            labels = {"kubernetes.io/service-name": svc["name"]}
            if owner["kind"] == "Gateway":
                labels = {
                    "io.cilium.gateway/owning-gateway": owner["name"],
                    "gateway.networking.k8s.io/gateway-name": owner["name"],
                    **labels,
                }
                api = "gateway.networking.k8s.io/v1beta1"
                kind_key = "gateway"
            else:
                labels = {"cilium.io/ingress": "true", **labels}
                api = "networking.k8s.io/v1"
                kind_key = "ingress"
            out.append(
                {
                    "apiVersion": "discovery.k8s.io/v1",
                    "kind": "EndpointSlice",
                    "metadata": k8s_meta(
                        svc["name"],
                        uid,
                        "2026-10-07T09:00:00Z",
                        svc["namespace"],
                        labels=labels,
                        ownerReferences=[
                            {
                                "apiVersion": api,
                                "kind": owner["kind"],
                                "name": owner["name"],
                                "uid": str(
                                    uuid.uuid5(
                                        NS,
                                        f"aci-pilot/{kind_key}/{svc['namespace']}/{owner['name']}",
                                    )
                                ),
                                "controller": True,
                            }
                        ],
                    ),
                    "addressType": "IPv4",
                    "endpoints": [
                        {
                            "addresses": ["192.192.192.192"],
                            "conditions": {"ready": True},
                        }
                    ],
                    "ports": [{"port": 9999}],
                }
            )
            continue
        backends = [
            p
            for p in s.pods
            if p["namespace"] == svc["namespace"]
            and all(p["labels"].get(k) == v for k, v in svc["selector"].items())
        ]
        out.append(
            {
                "apiVersion": "discovery.k8s.io/v1",
                "kind": "EndpointSlice",
                "metadata": k8s_meta(
                    name,
                    uid,
                    "2026-10-07T09:00:05Z",
                    svc["namespace"],
                    labels={
                        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
                        "kubernetes.io/service-name": svc["name"],
                    },
                    ownerReferences=svc_ref,
                    generateName=f"{svc['name']}-",
                ),
                "addressType": "IPv4",
                "endpoints": [
                    {
                        "addresses": [p["ip"]],
                        "conditions": {
                            "ready": True,
                            "serving": True,
                            "terminating": False,
                        },
                        "nodeName": p["node"],
                        "targetRef": {
                            "kind": "Pod",
                            "name": p["name"],
                            "namespace": p["namespace"],
                            "uid": p["uid"],
                        },
                    }
                    for p in sorted(backends, key=lambda p: p["ip"])
                ],
                "ports": [
                    {
                        "name": port["name"],
                        "port": port["target_port"]
                        if isinstance(port["target_port"], int)
                        else port["port"],
                        "protocol": port["protocol"],
                    }
                    for port in svc["ports"]
                ],
            }
        )
    return out


def ingress_object(ing: dict) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": k8s_meta(
            ing["name"],
            ing["uid"],
            "2026-10-07T09:00:00Z",
            ing["namespace"],
            annotations=ing.get("annotations"),
        ),
        "spec": {
            "ingressClassName": ing["class"],
            "rules": [
                {
                    "host": ing["host"],
                    "http": {
                        "paths": [
                            {
                                "path": ing["path"],
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": ing["backend"]["service"],
                                        "port": {"number": ing["backend"]["port"]},
                                    }
                                },
                            }
                        ]
                    },
                }
            ],
            "tls": [{"hosts": [ing["host"]], "secretName": ing["tls_secret"]}],
        },
        "status": {"loadBalancer": {"ingress": [{"ip": ing["lb_ip"]}]}},
    }


def gateway_object(gw: dict) -> dict:
    lst = gw["listener"]
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": k8s_meta(
            gw["name"], gw["uid"], "2026-10-07T09:00:00Z", gw["namespace"]
        ),
        "spec": {
            "gatewayClassName": gw["class"],
            "listeners": [
                {
                    "name": lst["name"],
                    "protocol": lst["protocol"],
                    "port": lst["port"],
                    "hostname": lst["hostname"],
                    "tls": {
                        "mode": "Terminate",
                        "certificateRefs": [
                            {"group": "", "kind": "Secret", "name": lst["tls_secret"]}
                        ],
                    },
                    "allowedRoutes": {"namespaces": {"from": "Same"}},
                }
            ],
        },
        "status": {"addresses": [{"type": "IPAddress", "value": gw["address"]}]},
    }


def httproute_object(r: dict) -> dict:
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": k8s_meta(
            r["name"], r["uid"], "2026-10-07T09:00:00Z", r["namespace"]
        ),
        "spec": {
            "parentRefs": [
                {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": r["gateway"],
                }
            ],
            "hostnames": [r["hostname"]],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": r["path"]}}],
                    "backendRefs": [
                        {
                            "group": "",
                            "kind": "Service",
                            "name": r["backend"]["service"],
                            "port": r["backend"]["port"],
                            "weight": 1,
                        }
                    ],
                }
            ],
        },
    }


def node_object(n: dict) -> dict:
    # Cilium node annotations pkg/annotation/k8s.go:55,73 (network.cilium.io/ipv4-pod-cidr, ipv4-Ingress-ip).
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": k8s_meta(
            n["name"],
            n["uid"],
            "2026-09-01T00:00:00Z",
            labels={
                "kubernetes.io/hostname": n["name"],
                "kubernetes.io/os": "linux",
                "kubernetes.io/arch": "amd64",
            },
            annotations={
                "network.cilium.io/ipv4-pod-cidr": n["pod_cidr"],
                "network.cilium.io/ipv4-Ingress-ip": n["ingress_ip"],
            },
        ),
        "spec": {},
        "status": {
            "addresses": [
                {"type": "InternalIP", "address": n["ip"]},
                {"type": "Hostname", "address": n["name"]},
            ],
            "conditions": [
                {"type": "Ready", "status": "True", "reason": "KubeletReady"}
            ],
        },
    }


# kube:object:<resource> (watch) — chart transform/add_sourcetype
# templates/config/_otel-k8s-cluster-receiver-config.tpl:209-214; envelope as kube_pods().
def aci_kube_objects(s: AciScenario) -> list[dict]:
    k8s = s.doc["kubernetes"]
    out = []

    def emit(at: datetime, resource: str, kind: str, obj: dict) -> None:
        fields = {
            "metric_source": "kubernetes",
            "k8s.cluster.name": s.cluster,
            "k8s.resource.name": resource,
            "event.domain": "k8s",
            "event.name": obj["metadata"]["name"],
        }
        if obj["metadata"].get("namespace"):
            fields = {"k8s.namespace.name": obj["metadata"]["namespace"], **fields}
        out.append(
            envelope(
                epoch(at),
                CLUSTER_RECEIVER_NODE,
                "kubernetes",
                f"kube:object:{resource}",
                "k8s",
                {"type": kind, "object": obj},
                fields,
            )
        )

    for p in s.pods:
        start = parse(p["start"])
        emit(start, "pods", "ADDED", pod_object(s, p, "Pending"))
        emit(
            start + timedelta(seconds=3),
            "pods",
            "MODIFIED",
            pod_object(s, p, "Running"),
        )
    created = parse("2026-10-07T09:00:00Z")
    for svc in k8s["services"]:
        emit(created, "services", "ADDED", service_object(s, svc, with_status=False))
        if svc["type"] == "LoadBalancer":
            # Cilium LB IPAM assigns status.loadBalancer.ingress after creation.
            emit(
                created + timedelta(seconds=1),
                "services",
                "MODIFIED",
                service_object(s, svc, with_status=True),
            )
    for eps in endpointslice_objects(s):
        emit(
            parse(eps["metadata"]["creationTimestamp"]), "endpointslices", "ADDED", eps
        )
    for ing in k8s["ingresses"]:
        emit(created, "ingresses", "ADDED", ingress_object(ing))
    for gw in k8s["gateways"]:
        emit(created, "gateways", "ADDED", gateway_object(gw))
    for r in k8s["httproutes"]:
        emit(created, "httproutes", "ADDED", httproute_object(r))
    # Kubelet reports node status every nodeStatusReportFrequency (default 5m) -> MODIFIED events.
    for at in polls(s.window_start - timedelta(minutes=15), s.window_end):
        for n in k8s["nodes"]:
            emit(at, "nodes", "MODIFIED", node_object(n))
    return out


def hubble_endpoint(s: AciScenario, ref: str) -> dict:
    if ref in RESERVED_IDENTITIES:
        return {"identity": RESERVED_IDENTITIES[ref], "labels": [ref]}
    p = s.pod_by_name[ref]
    labels = sorted(
        [f"k8s:{k}={v}" for k, v in p["labels"].items() if k != "pod-template-hash"]
        + [
            f"k8s:io.kubernetes.pod.namespace={p['namespace']}",
            f"k8s:io.cilium.k8s.policy.cluster={s.cluster}",
            "k8s:io.cilium.k8s.policy.serviceaccount=default",
        ]
    )
    return {
        "ID": stable_int(p["uid"], "endpoint", digits=4),
        "identity": 10000 + stable_int(p["owner_name"], "identity", digits=4),
        "cluster_name": s.cluster,
        "namespace": p["namespace"],
        "labels": labels,
        "pod_name": p["name"],
        "workloads": [
            {"name": p["owner_name"].rsplit("-", 1)[0], "kind": "Deployment"}
        ],
    }


# cilium:hubble:flow — Hubble static exporter JSON lines (observer.proto ExportEvent {flow, node_name,
# time}) marshalled with protojson UseProtoNames (api/v1/flow/flow.pb.json.go@v1.20.2); Flow fields
# api/v1/flow/flow.proto@v1.20.2; SNAT source_xlated pkg/hubble/parser/threefour/parser.go:251-264.
# Shipped by the Helm chart logsCollection.extraFileLogs filelog receiver (values.yaml:780-791;
# templates/config/_otel-agent.tpl:745-753, logs/host pipeline :1215; resource k8s.node.name/
# k8s.cluster.name :859-868); body = the JSON line, source = com.splunk.source, time = observed.
def hubble_flows(s: AciScenario) -> list[dict]:
    otel = s.doc["otel"]
    out = []
    for conv in s.doc["conversations"]:
        for h in conv.get("hubble", []):
            at = parse(h["time"])
            s_ip, s_port = endpoint(h["src"])
            d_ip, d_port = endpoint(h["dst"])
            ip = {"source": s_ip}
            tcp = {
                "source_port": h.get("src_port_xlated", s_port),
                "destination_port": d_port,
            }
            if h.get("src_xlated"):
                ip["source_xlated"] = h["src_xlated"]
            ip.update({"destination": d_ip, "ipVersion": "IPv4"})
            if h.get("syn"):
                tcp["flags"] = {"SYN": True}
            l7 = h["type"] == "L7"
            flow = {
                "time": iso_proto(at),
                "uuid": str(
                    uuid.uuid5(
                        NS, f"hubble/{conv['id']}/{h['node']}/{h['time']}/{h['type']}"
                    )
                ),
                "verdict": "FORWARDED",
                "IP": ip,
                "l4": {"TCP": tcp},
                "source": hubble_endpoint(s, h["src_ep"]),
                "destination": hubble_endpoint(s, h["dst_ep"]),
                "Type": h["type"],
                "node_name": f"{s.cluster}/{h['node']}",
            }
            if l7:
                http = h["http"]
                traceparent = f"00-{h['trace_id']}-{stable_hex(h['trace_id'], 'envoy', length=16)}-01"
                flow["l7"] = {
                    "type": "REQUEST",
                    "http": {
                        "method": http["method"],
                        "url": http["url"],
                        "protocol": http["protocol"],
                        "headers": [
                            {"key": "Traceparent", "value": traceparent},
                            {"key": "X-Envoy-External-Address", "value": http["xff"]},
                            {"key": "X-Forwarded-For", "value": http["xff"]},
                            {"key": "X-Forwarded-Proto", "value": "https"},
                        ],
                    },
                }
                flow["event_type"] = {"type": 129}
                flow["traffic_direction"] = "INGRESS"
                flow["is_reply"] = False
                flow["trace_context"] = {"parent": {"trace_id": h["trace_id"]}}
                flow["Summary"] = f"{http['protocol']} {http['method']} {http['url']}"
            else:
                point = h["point"]
                flow["event_type"] = {
                    "type": 4,
                    "sub_type": 0 if point == "TO_ENDPOINT" else 11,
                }
                flow["traffic_direction"] = (
                    "INGRESS" if point == "TO_ENDPOINT" else "EGRESS"
                )
                flow["trace_observation_point"] = point
                flow["trace_reason"] = "NEW"
                flow["is_reply"] = False
                flow["Summary"] = "TCP Flags: SYN"
            line = {
                "flow": flow,
                "node_name": f"{s.cluster}/{h['node']}",
                "time": iso_proto(at),
            }
            out.append(
                envelope(
                    epoch(at + HUBBLE_FILE_DELAY),
                    h["node"],
                    otel["hubble_file"],
                    otel["hubble_sourcetype"],
                    otel["hubble_index"],
                    json.dumps(line, separators=(",", ":")),
                    {
                        "k8s.node.name": h["node"],
                        "k8s.cluster.name": s.cluster,
                        "log.file.path": otel["hubble_file"],
                    },
                )
            )
    return out


# cisco:isovalent processConnect — same shape and citations as isovalent().
def aci_isovalent(s: AciScenario) -> list[dict]:
    out = []
    for conv in s.doc["conversations"]:
        for rec in conv.get("isovalent", []):
            pod = s.pod_by_name[rec["pod"]]
            c_ip, c_port = endpoint(rec["src"])
            d_ip, d_port = endpoint(rec["dst"])
            at = parse(rec["time"])
            workload = pod["service"] or pod["owner_name"].rsplit("-", 1)[0]
            binary = f"/app/{workload}"
            event = {
                "process_connect": {
                    "process": {
                        "exec_id": exec_id(pod["node"], pod, binary),
                        "pid": stable_int(pod["uid"], "pid", digits=5),
                        "uid": 0,
                        "cwd": "/",
                        "binary": binary,
                        "arguments": "",
                        "pod": {
                            "namespace": pod["namespace"],
                            "name": pod["name"],
                            "container": {
                                "id": "containerd://"
                                + stable_hex(pod["uid"], "container"),
                                "name": workload,
                                "image": {
                                    "id": "sha256:" + stable_hex(pod["uid"], "image"),
                                    "name": f"registry.example/{pod['namespace']}/{workload}:1.0.0",
                                },
                            },
                            "workload_kind": "Deployment",
                        },
                    },
                    "source_ip": c_ip,
                    "source_port": c_port,
                    "destination_ip": d_ip,
                    "destination_port": d_port,
                    "protocol": conv["transport"].upper(),
                    "sock_cookie": str(
                        stable_int(conv["id"], rec["src"], "sock", digits=15)
                    ),
                },
                "node_name": pod["node"],
                "time": iso_proto(at),
            }
            out.append(
                envelope(
                    epoch(at),
                    pod["node"],
                    ISOVALENT_SOURCE,
                    "cisco:isovalent",
                    "cisco_isovalent",
                    event,
                )
            )
    return out


# Spans — same exporter format and citations as otel_traces(); pods are named explicitly per span.
def aci_otel_traces(s: AciScenario) -> list[dict]:
    otel = s.doc["otel"]
    out = []
    for trace in s.doc["traces"]:
        for sp in trace["spans"]:
            start, end = parse(sp["start"]), parse(sp["end"])
            pod = s.pod_by_name[sp["pod"]]
            event = {
                "trace_id": trace["trace_id"],
                "span_id": sp["span_id"],
                "parent_span_id": sp["parent"] or "",
                "name": sp["name"],
                "attributes": sp["attributes"],
                "end_time": epoch_ns(end),
                "kind": sp["kind"],
                "status": {"message": "", "code": "STATUS_CODE_UNSET"},
                "start_time": epoch_ns(start),
            }
            fields = {
                "service.name": sp["service"],
                "deployment.environment.name": s.env,
                "k8s.cluster.name": s.cluster,
                "k8s.namespace.name": pod["namespace"],
                "k8s.node.name": pod["node"],
                "k8s.pod.name": pod["name"],
                "k8s.pod.uid": pod["uid"],
                "k8s.pod.labels.app": pod["labels"].get("app", ""),
            }
            out.append(
                envelope(
                    epoch(start),
                    pod["node"],
                    "kubernetes",
                    otel["traces_sourcetype"],
                    "otel_traces",
                    event,
                    fields,
                )
            )
    return out


def main_aci() -> int:
    s = AciScenario(json.loads((RAW_ACI / "scenario.json").read_text()))
    aci_stats, aci_class = aci_collections(s)
    outputs = {
        "stream_netflow.ndjson": aci_netflow(s),
        "nd_flows.ndjson": aci_nd_flows(s),
        "nd_endpoints.ndjson": aci_nd_endpoints(s),
        "aci_stats.ndjson": aci_stats,
        "aci_class.ndjson": aci_class,
        "kube_objects.ndjson": aci_kube_objects(s),
        "hubble_flows.ndjson": hubble_flows(s),
        "isovalent.ndjson": aci_isovalent(s),
        "otel_traces.ndjson": aci_otel_traces(s),
    }
    for name, events in outputs.items():
        print(f"{name}: {write(name, events, RAW_ACI)}")
    return 0


def write(name: str, events: list[dict], out_dir: Path = RAW) -> int:
    events = sorted(events, key=lambda e: e["time"])
    lines = [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in events]
    (out_dir / name).write_text("".join(line + "\n" for line in lines))
    return len(lines)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=("nxos", "aci"),
        default="nxos",
        help="nxos: fixtures/raw/ (default); aci: the ACI pilot in fixtures/raw-aci/",
    )
    if parser.parse_args().scenario == "aci":
        return main_aci()
    s = Scenario(json.loads((RAW / "scenario.json").read_text()))
    aci_stats, aci_class = aci(s)
    netflow, netflow_late = stream_netflow(s)
    (RAW / "late").mkdir(exist_ok=True)
    outputs = {
        "stream_netflow.ndjson": netflow,
        "late/stream_netflow.ndjson": netflow_late,
        "nd_flows.ndjson": nd_flows(s),
        "nd_endpoints.ndjson": nd_endpoints(s),
        "aci_stats.ndjson": aci_stats,
        "aci_class.ndjson": aci_class,
        "nexus9k.ndjson": nexus9k(s),
        "ftd_estreamer.ndjson": ftd(s),
        "isovalent.ndjson": isovalent(s),
        "kube_object_pods.ndjson": kube_pods(s),
        "otel_traces.ndjson": otel_traces(s),
    }
    for name, events in outputs.items():
        print(f"{name}: {write(name, events)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
