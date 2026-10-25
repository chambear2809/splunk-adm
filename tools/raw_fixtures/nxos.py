"""NX-OS, NetFlow, FTD, Isovalent, Kubernetes, and OTel fixture builders."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import timedelta
from datetime import timezone
from datetime import datetime
from .common import (
    CLUSTER_RECEIVER_NODE,
    EXPORTER_BOOT,
    FMC_HOST,
    FTD_INPUT,
    HEAVY_FORWARDER,
    ISOVALENT_SOURCE,
    NETFLOW_INACTIVE_TIMEOUT_MS,
    NS,
    PROTO_NUMBER,
    STREAM_FORWARDER,
    Scenario,
    TCP_FLAGS_FULL_SESSION,
    VMM_CONTROLLER,
    derived_mac,
    endpoint,
    envelope,
    epoch,
    epoch_ns,
    ipv4_mapped_full,
    iso_ms,
    iso_proto,
    iso_s,
    iso_us,
    legs,
    naive_local,
    next_poll,
    packets,
    parse,
    polls,
    segments,
    stable_hex,
    stable_int,
)


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
            # "show version" (default/inputs.conf:143). Its JSON has only scalar
            # top-level keys, which the TA emits as one {key: value} list item each
            # (bin/cisco_nexus_9k.py:155-180); proc_board_id follows nxos_ver_str.
            emit(
                "cisco_nexus_9k://nxversion",
                "nxversion",
                [{"nxos_ver_str": sw["nxos"]}, {"proc_board_id": sw["serial"]}],
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
