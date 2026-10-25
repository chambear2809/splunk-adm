"""ACI, Kubernetes, Hubble, and OTel fixture builders and prior-window transformations."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import timedelta
from datetime import timezone
from datetime import datetime
from pathlib import Path
from .common import (
    ACI_PREV_RAW,
    CLUSTER_RECEIVER_NODE,
    EXPORTER_BOOT,
    HEAVY_FORWARDER,
    ISOVALENT_SOURCE,
    NETFLOW_INACTIVE_TIMEOUT_MS,
    NS,
    POLL_INTERVAL,
    PROTO_NUMBER,
    RAW_ACI,
    STREAM_FORWARDER,
    TCP_FLAGS_FULL_SESSION,
    VMM_CONTROLLER,
    derived_mac,
    endpoint,
    envelope,
    epoch,
    epoch_ns,
    iso_ms,
    iso_proto,
    iso_us,
    next_poll,
    packets,
    parse,
    polls,
    stable_hex,
    stable_int,
    write,
)
from .nxos import (
    aci_event,
    aci_ts,
    exec_id,
    pod_object,
)


_ISO_DATE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>Z|[+-]\d{2}:?\d{2})$"
)

_ISO_DATE_INLINE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
)


def shift_iso_dates(value, seconds: int = -900):
    """Recursively shift scenario ISO timestamps while preserving their spelling."""
    if isinstance(value, dict):
        return {key: shift_iso_dates(item, seconds) for key, item in value.items()}
    if isinstance(value, list):
        return [shift_iso_dates(item, seconds) for item in value]
    if not isinstance(value, str):
        return value
    match = _ISO_DATE.fullmatch(value)
    if not match:
        return value
    try:
        shifted = parse(value) + timedelta(seconds=seconds)
    except ValueError:
        return value
    fraction = match.group("fraction")
    rendered = shifted.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        rendered += f".{shifted.microsecond:06d}"[: len(fraction)]
    return rendered + match.group("zone")


def shift_networking_fixed_timestamps(value, delta: timedelta):
    """Rebase legacy fixed Oct 7 body timestamps in combined networking events."""
    if isinstance(value, dict):
        return {
            key: shift_networking_fixed_timestamps(item, delta)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [shift_networking_fixed_timestamps(item, delta) for item in value]
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(
            shift_networking_fixed_timestamps(parsed, delta), ensure_ascii=False
        )

    def shift_match(match: re.Match) -> str:
        stamp = match.group(0)
        if not stamp.startswith("2026-10-07T"):
            return stamp
        return shift_iso_dates(stamp, int(delta.total_seconds()))

    return _ISO_DATE_INLINE.sub(shift_match, value)


def previous_aci_scenario(base: dict | None = None) -> dict:
    """Return the preceding 15-minute ACI window, without the blocked c8 conversation."""
    source = (
        base
        if base is not None
        else json.loads((RAW_ACI / "scenario.json").read_text())
    )
    previous = shift_iso_dates(json.loads(json.dumps(source)))
    previous["conversations"] = [
        conversation
        for conversation in previous["conversations"]
        if conversation.get("id") != "c8-blocked-db"
    ]
    return previous


ACI_PROTO_NUMBER = {**PROTO_NUMBER, "ipip": 4}

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

ACI_TOPOLOGY_INPUT = "cisco_nexus_aci://classInfo_adm"

ACI_NETWORK_INPUT = "cisco_nexus_aci://classInfo_adm_network"

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


def leg_segments(leg: dict, start: datetime, end: datetime):
    """NetFlow records of one leg: the whole leg, or one record per active-timeout segment.

    A leg may override the conversation's start/end ("start", "end"); "segments" lists
    [start, end] pairs of successive exports of one long flow (bytes split evenly).
    """
    start = parse(leg["start"]) if leg.get("start") else start
    end = parse(leg["end"]) if leg.get("end") else end
    segs = leg.get("segments")
    if not segs:
        return [((start, end), leg["bytes"])]
    return [((parse(a), parse(b)), leg["bytes"] // len(segs)) for a, b in segs]


def leg_endpoints(leg: dict) -> tuple[str, int | None, str, int | None]:
    s_ip, s_port = endpoint(leg["src"])
    d_ip, d_port = endpoint(leg["dst"])
    return s_ip, s_port, d_ip, d_port


def split_at(spec: str) -> tuple[str, str]:
    leaf, port = spec.split(":", 1)
    return leaf, port


def aci_netflow(s: AciScenario) -> list[dict]:
    out, seq = [], {}
    router_mac = s.fabric["router_mac"]
    for conv in s.doc["conversations"]:
        start, end = parse(conv["start"]), parse(conv["end"])
        records = [
            (leg, *span, b)
            for leg in conv["wire"]
            if leg.get("netflow") is not False
            for span, b in leg_segments(leg, start, end)
        ]
        for leg, start, end, nbytes in records:
            leaf, port = split_at(leg["ingress"])
            sw = s.switches[leaf]
            s_ip, s_port, d_ip, d_port = leg_endpoints(leg)
            seq[leaf] = seq.get(leaf, 2000) + 1
            rel_start = int((start - EXPORTER_BOOT).total_seconds() * 1000)
            rel_end = int((end - EXPORTER_BOOT).total_seconds() * 1000)
            proto = leg["proto"]
            ingress_vlan = s.vlan(leaf, port)
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
                "bytes": nbytes,
                "packets": packets(nbytes),
                "tcp_flags": TCP_FLAGS_FULL_SESSION if proto == "tcp" else 0,
                "flow_end_rel": rel_end,
                "flow_start_rel": rel_start,
                "input_snmpidx": nxos_ifindex(port),
                # The scenario has no configured access encap on some routed
                # L3Out interfaces, so omit unavailable fixture VLAN data.
                **({"ingress_vlan": ingress_vlan} if ingress_vlan else {}),
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
                "ts": iso_ms(parse(leg["nd_start"]) if leg.get("nd_start") else start),
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


def aci_nd_endpoints(s: AciScenario, created_at: datetime | None = None) -> list[dict]:
    nd = s.doc["nexus_dashboard"]
    created = created_at or parse("2026-10-07T09:00:00Z")
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


def fvrsbd_attrs(dn: str, bd_name: str, t_dn: str) -> list[tuple[str, object]]:
    """Grounded fvRsBd relation fields from the APIC MIM classInfo writer.

    The relation is emitted beneath an fvAEPg. ``tnFvBDName`` is the APIC
    relation's BD name field; ``tDn`` is the resolved fvBD DN.
    Keep this list limited to attributes present in the MIM relation and the
    existing TA relation writer vocabulary.
    """
    return sorted(
        [
            ("dn", dn),
            ("forceResolve", "yes"),
            ("rType", "mo"),
            ("state", "formed"),
            ("status", ""),
            ("tCl", "fvBD"),
            ("tDn", t_dn),
            ("tType", "mo"),
            ("tnFvBDName", bd_name),
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
                                    (
                                        "sFromPort",
                                        aci_port_value(e.get("s_from", "unspecified")),
                                    ),
                                    (
                                        "sToPort",
                                        aci_port_value(e.get("s_to", "unspecified")),
                                    ),
                                    ("stateful", "no"),
                                    ("tcpRules", e.get("tcp_rules", "")),
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


def aci_collections(
    s: AciScenario, timestamp_delta: timedelta = timedelta(0)
) -> tuple[list[dict], list[dict]]:
    f = s.fabric
    apic = f["apic"]["oob"]
    pod_id = f["pod_id"]
    stats, klass = [], []
    seen_from = s.window_start - timedelta(minutes=15)
    mod_ts = aci_ts(ACI_MOD_TS + timestamp_delta)
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
        # fvRsBd is collected by the optional network classInfo input.  Emit
        # one resolved relation per EPG per poll so the endpoint's EPG and its
        # bridge domain remain linkable even when the relation arrives before
        # a later endpoint snapshot.
        for epg_key, epg in sorted(s.epgs.items()):
            ap, epg_name = epg_key.split("/")
            epg_dn = f"uni/tn-{s.tenant}/ap-{ap}/epg-{epg_name}"
            bd_dn = f"uni/tn-{s.tenant}/BD-{epg['bd']}"
            emit(
                klass,
                ACI_NETWORK_INPUT,
                "cisco:dc:aci:class",
                at,
                fvrsbd_attrs(f"{epg_dn}/rsbd", epg["bd"], bd_dn),
                "fvRsBd",
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
        for acl in conv.get("acl") or []:
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
            # A record stays in the leaf's ACL-log buffer and can be reported by later polls too.
            for k in range(1 + acl.get("repolls", 0)):
                emit(
                    klass,
                    "cisco_nexus_aci://classInfo_fvRsCEpToPathEp",
                    "cisco:dc:aci:class",
                    next_poll(at) + k * POLL_INTERVAL,
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
                    "allowedRoutes": {
                        "namespaces": {"from": gw.get("allowed_routes_from", "Same")}
                    },
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
                    **(
                        {"namespace": r["gateway_namespace"]}
                        if r.get("gateway_namespace")
                        else {}
                    ),
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


def aci_kube_objects(s: AciScenario, created_at: datetime | None = None) -> list[dict]:
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
    created = created_at or parse("2026-10-07T09:00:00Z")
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
    endpoint_slices = endpointslice_objects(s)
    if created_at is not None:
        creation_shift = int(
            (created_at - parse("2026-10-07T09:00:00Z")).total_seconds()
        )
        endpoint_slices = [
            shift_iso_dates(eps, creation_shift) for eps in endpoint_slices
        ]
    for eps in endpoint_slices:
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
                            {
                                "key": "X-Envoy-External-Address",
                                "value": http.get("external_address", http["xff"]),
                            },
                            {
                                "key": "X-Forwarded-For",
                                "value": http.get("xff_header", http["xff"]),
                            },
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


def aci_isovalent(s: AciScenario, hec_source: str = ISOVALENT_SOURCE) -> list[dict]:
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
                    hec_source,
                    "cisco:isovalent",
                    "cisco_isovalent",
                    event,
                )
            )
    return out


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


def main_aci(out_dir: Path = RAW_ACI) -> int:
    s = AciScenario(json.loads((RAW_ACI / "scenario.json").read_text()))
    outputs = aci_outputs(s)
    for name, events in outputs.items():
        print(f"{name}: {write(name, events, out_dir)}")
    main_aci_edge(s.doc, out_dir)
    return 0


def aci_outputs(s: AciScenario) -> dict[str, list[dict]]:
    aci_stats, aci_class = aci_collections(s)
    return {
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


def main_aci_previous() -> int:
    scenario = previous_aci_scenario()
    s = AciScenario(scenario)
    for name, events in aci_outputs(s).items():
        print(f"{name}: {write(name, events, ACI_PREV_RAW)}")
    return 0


def aci_edge_doc(base: dict, edge: dict) -> dict:
    """The ACI scenario with the edge-case additions, window, conversations and traces."""
    doc = json.loads(json.dumps(base))
    add = edge["add"]
    doc["vms"] += add.get("vms", [])
    doc["hypervisors"] += add.get("hypervisors", [])
    doc["fabric"]["contracts"] += add.get("contracts", [])
    k8s = doc["kubernetes"]
    for key in ("nodes", "pods", "services", "gateways", "httproutes"):
        k8s[key] += add.get(key, [])
    doc["window"] = edge["window"]
    doc["conversations"] = edge["conversations"]
    doc["traces"] = edge["traces"]
    return doc


def aci_edge_kube_objects(s: AciScenario, edge: dict) -> list[dict]:
    add = edge["add"]
    out = []

    def emit(at: datetime, resource: str, kind: str | None, obj: dict) -> None:
        fields = {
            "metric_source": "kubernetes",
            "k8s.cluster.name": s.cluster,
            "k8s.resource.name": resource,
            "event.domain": "k8s",
            "event.name": obj["metadata"]["name"],
        }
        if obj["metadata"].get("namespace"):
            fields = {"k8s.namespace.name": obj["metadata"]["namespace"], **fields}
        body = obj if kind is None else {"type": kind, "object": obj}
        out.append(
            envelope(
                epoch(at),
                CLUSTER_RECEIVER_NODE,
                "kubernetes",
                f"kube:object:{resource}",
                "k8s",
                body,
                fields,
            )
        )

    created = parse("2026-10-07T09:00:00Z")
    for p in add.get("pods", []):
        start = parse(p["start"])
        emit(start, "pods", "ADDED", pod_object(s, p, "Pending"))
        emit(
            start + timedelta(seconds=3),
            "pods",
            "MODIFIED",
            pod_object(s, p, "Running"),
        )
    new_svcs = {(v["namespace"], v["name"]) for v in add.get("services", [])}
    for svc in add.get("services", []):
        emit(created, "services", "ADDED", service_object(s, svc, with_status=False))
        if svc["type"] == "LoadBalancer":
            emit(
                created + timedelta(seconds=1),
                "services",
                "MODIFIED",
                service_object(s, svc, with_status=True),
            )
    slices = {}
    for eps in endpointslice_objects(s):
        svc_name = eps["metadata"]["labels"]["kubernetes.io/service-name"]
        key = (eps["metadata"]["namespace"], svc_name)
        slices[key] = eps
        if key in new_svcs:
            emit(
                parse(eps["metadata"]["creationTimestamp"]),
                "endpointslices",
                "ADDED",
                eps,
            )
    for gw in add.get("gateways", []):
        emit(created, "gateways", "ADDED", gateway_object(gw))
    for r in add.get("httproutes", []):
        emit(created, "httproutes", "ADDED", httproute_object(r))
    for at in polls(s.window_start - timedelta(minutes=10), s.window_end):
        for n in s.doc["kubernetes"]["nodes"]:
            emit(at, "nodes", "MODIFIED", node_object(n))
    late = []
    for upd in edge["updates"]:
        eps = json.loads(json.dumps(slices[("shop", upd["endpointslice"])]))
        if upd.get("not_ready"):
            for ep in eps["endpoints"]:
                ep["conditions"] = {
                    "ready": False,
                    "serving": False,
                    "terminating": True,
                }
        before = len(out)
        emit(
            parse(upd["time"]),
            "endpointslices",
            None if upd["kind"] == "PULL" else upd["kind"],
            eps,
        )
        if upd["batch"] == "late":
            late.append(out.pop(before))
    return out, late


def main_aci_edge(base: dict, out_dir: Path = RAW_ACI) -> None:
    edge = json.loads((RAW_ACI / "edge-cases.json").read_text())
    s = AciScenario(aci_edge_doc(base, edge))
    end = epoch(s.window_end)
    aci_stats, aci_class = aci_collections(s)
    kube, kube_late = aci_edge_kube_objects(s, edge)
    new_owners = {v["ip"] for v in edge["add"].get("vms", [])} | {
        n["ip"] for n in edge["add"].get("nodes", [])
    }
    nd_endpoints_new = [
        e for e in aci_nd_endpoints(s) if json.loads(e["event"])["ip"][0] in new_owners
    ]
    outputs = {
        "stream_netflow.ndjson": aci_netflow(s),
        "nd_flows.ndjson": aci_nd_flows(s),
        "nd_endpoints.ndjson": nd_endpoints_new,
        "aci_stats.ndjson": aci_stats,
        "aci_class.ndjson": aci_class,
        "kube_objects.ndjson": kube,
        "hubble_flows.ndjson": hubble_flows(s),
        "isovalent.ndjson": aci_isovalent(s),
        "otel_traces.ndjson": aci_otel_traces(s),
    }
    edge_dir, late_dir = out_dir / "edge", out_dir / "edge" / "late"
    late_dir.mkdir(parents=True, exist_ok=True)
    late = {"kube_objects.ndjson": kube_late}
    for name, events in outputs.items():
        # Later polls (ACL-log re-reports) belong to the batch indexed after the edge window.
        late.setdefault(name, []).extend(e for e in events if e["time"] > end)
        events = [e for e in events if e["time"] <= end]
        print(f"edge/{name}: {write(name, events, edge_dir)}")
    for name, events in late.items():
        if events:
            print(f"edge/late/{name}: {write(name, events, late_dir)}")
