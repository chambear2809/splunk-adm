"""Splunk Add-on for VMware 4.2.1 inventory events and a VDS IPFIX record.

Event shape follows research/extracted/splunk-add-on-for-vmware_421/Splunk_TA_vmware:
- property sets: bin/vim25/inventory.py:34-71 (VirtualMachine config/guest/network/summary;
  HostSystem name/network/summary, plus hostsystem_inv_config additions, inventory.py:358,
  default/ta_vmware_collection.conf:51-53);
- flattening: bin/vim25/utils.py:169-199 (CheckAttribute: MOR -> {moid,type}, dotted property
  names -> nested dicts, suds arrays -> {"<Type>": [...]}) and utils.py:66-98 (Folderize), ported
  below as ``folderize``; moid/type/rootFolder/collectionVersion from inventory.py:417-434;
- handler additions: bin/inventory_handlers.py:93-102,137-187 (vm_id, vm_name, hypervisor_name,
  hypervisor_id, ip from config.network.vnic, datacenter, cluster, runtime host name/uuid);
- sourcetype/source: inventory_handlers.py (vmware:inv:hostsystem / vmware:inv:vm, source
  VMInv:<type>), index default vmware-inv (ta_vmware_collection.conf:14).

The inner vSphere API member names (HostNetworkInfo vswitch/portgroup/pnic/proxySwitch,
VirtualEthernetCard backing.port, GuestNicInfo) come from the vSphere Web Services API, not the
TA package; they are listed as unverified in fixtures/raw-vmware/FIELDS.md.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from .common import ROOT, envelope, epoch, parse, write

RAW_VMWARE = ROOT / "fixtures" / "raw-vmware"
INV_INDEX = "vmware-inv"


def folderize(value):
    """Port of Splunk_TA_vmware bin/vim25/utils.py:66-98 (list-of-dict column merge)."""
    if isinstance(value, list):
        is_complex = False
        output: list = []
        merged: dict = {}
        for item in value:
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, (list, dict)):
                        is_complex = True
                    merged.setdefault(k, []).append(v)
            elif item is not None:
                output.append(item)
        if merged and is_complex:
            output.append(folderize(merged))
        else:
            output = value
        if len(output) == 1:
            output = output[0]
        return output
    if isinstance(value, dict):
        return {k: folderize(v) for k, v in value.items()}
    return value


def mor(moid: str, kind: str) -> dict:
    return {"moid": moid, "type": kind}


def full_object(changes: list[dict], obj: dict, root: str) -> dict:
    # inventory.py:423-433: ObjectUpdate -> dict, Folderize, then moid/type/rootFolder/version.
    item = folderize({"changeSet": changes, "kind": "enter", "obj": obj})
    item.pop("kind", None)
    item["moid"] = obj["moid"]
    item["type"] = obj["type"]
    item["rootFolder"] = {"moid": root}
    item["collectionVersion"] = "1"
    item.pop("obj", None)
    return item


def host_network(doc: dict, host: dict) -> dict:
    """HostNetworkInfo (config.network) as CheckAttribute renders suds arrays."""
    vds = {v["name"]: v for v in doc["vds"]}
    pnic_key = lambda d: f"key-vim.host.PhysicalNic-{d}"  # noqa: E731
    return {
        "pnic": {
            "PhysicalNic": [
                {"key": pnic_key(p["device"]), "device": p["device"], "mac": p["mac"]}
                for p in host["pnics"]
            ]
        },
        "vswitch": {
            "HostVirtualSwitch": [
                {
                    "name": s["name"],
                    "key": f"key-vim.host.VirtualSwitch-{s['name']}",
                    "pnic": {"string": [pnic_key(d) for d in s["pnics"]]},
                    "spec": {"bridge": {"nicDevice": {"string": s["pnics"]}}},
                }
                for s in host["vswitches"]
            ]
        },
        "portgroup": {
            "HostPortGroup": [
                {
                    "key": f"key-vim.host.PortGroup-{pg['name']}",
                    "vswitch": f"key-vim.host.VirtualSwitch-{s['name']}",
                    "spec": {
                        "name": pg["name"],
                        "vlanId": pg["vlan"],
                        "vswitchName": s["name"],
                    },
                }
                for s in host["vswitches"]
                for pg in s["portgroups"]
            ]
        },
        "proxySwitch": {
            "HostProxySwitch": [
                {
                    "dvsUuid": vds[p["vds"]]["uuid"],
                    "dvsName": p["vds"],
                    "key": vds[p["vds"]]["uuid"],
                    "pnic": {"string": [pnic_key(u["device"]) for u in p["uplinks"]]},
                    "uplinkPort": {
                        "KeyValue": [
                            {"key": u["port_key"], "value": u["name"]}
                            for u in p["uplinks"]
                        ]
                    },
                }
                for p in host["proxy_switches"]
            ]
        },
    }


def hostsystem(doc: dict, host: dict) -> dict:
    changes = [
        {"name": host["name"]},
        {
            "config": {
                "hyperThread": {"active": True, "available": True, "config": True}
            }
        },
        # Only with hostsystem_inv_config = config.network (ta_vmware_collection.conf:51-53).
        {"config": {"network": host_network(doc, host)}},
        {
            "summary": {
                "config": {
                    "name": host["name"],
                    "product": {"osType": "vmnix-x86", "version": host["version"]},
                },
                "hardware": {"uuid": host["uuid"], "numNics": len(host["pnics"])},
            }
        },
        {
            "vm": {
                "ManagedObjectReference": [
                    mor(v["moid"], "VirtualMachine")
                    for v in doc["vms"]
                    if v["host"] == host["name"]
                ]
            }
        },
    ]
    item = full_object(changes, mor(host["moid"], "HostSystem"), doc["root_folder"])
    # inventory_handlers.py:173-185
    item["hypervisor_name"] = host["name"]
    item["hypervisor_id"] = host["uuid"]
    item["ip"] = host["vmk_ip"]
    item["datacenter"] = {
        **mor(doc["datacenter"]["moid"], "Datacenter"),
        "name": doc["datacenter"]["name"],
    }
    item["cluster"] = {
        **mor(doc["cluster"]["moid"], "ClusterComputeResource"),
        "name": doc["cluster"]["name"],
    }
    return item


def virtual_machine(doc: dict, vm: dict) -> dict:
    hosts = {h["name"]: h for h in doc["hosts"]}
    vds = {v["name"]: v for v in doc["vds"]}
    host = hosts[vm["host"]]

    def backing(nic: dict) -> dict:
        if "vds" in nic:
            pg = next(
                p
                for p in vds[nic["vds"]]["portgroups"]
                if p["name"] == nic["portgroup"]
            )
            return {
                "port": {
                    "switchUuid": vds[nic["vds"]]["uuid"],
                    "portgroupKey": pg["key"],
                    "portKey": nic["port_key"],
                    "connectionCookie": 1000 + int(nic["port_key"]),
                }
            }
        return {"deviceName": nic["portgroup"], "network": mor("network-11", "Network")}

    devices = [
        {
            "key": 1000,
            "deviceInfo": {"label": "SCSI controller 0", "summary": "LSI Logic SAS"},
        }
    ]
    devices += [
        {
            "key": n["key"],
            "deviceInfo": {"label": n["label"], "summary": n["portgroup"]},
            "backing": backing(n),
            "macAddress": n["mac"],
            "addressType": "assigned",
        }
        for n in vm["nics"]
    ]
    changes = [
        {"name": vm["name"]},
        {
            "config": {
                "name": vm["name"],
                "instanceUuid": vm["instance_uuid"],
                "guestFullName": vm["guest"],
                "hardware": {"numCPU": 2, "device": {"VirtualDevice": devices}},
            }
        },
        {
            "guest": {
                "ipAddress": vm["nics"][0]["ip"],
                "net": {
                    "GuestNicInfo": [
                        {
                            "network": n["portgroup"],
                            "ipAddress": {"string": [n["ip"]]},
                            "macAddress": n["mac"],
                            "connected": True,
                            "deviceConfigId": n["key"],
                        }
                        for n in vm["nics"]
                    ]
                },
            }
        },
        {
            "network": {
                "ManagedObjectReference": [
                    next(
                        mor(p["moid"], "DistributedVirtualPortgroup")
                        for p in vds[n["vds"]]["portgroups"]
                        if p["name"] == n["portgroup"]
                    )
                    if "vds" in n
                    else mor("network-11", "Network")
                    for n in vm["nics"]
                ]
            }
        },
        {
            "summary": {
                "runtime": {
                    "host": mor(host["moid"], "HostSystem"),
                    "powerState": "poweredOn",
                }
            }
        },
    ]
    item = full_object(changes, mor(vm["moid"], "VirtualMachine"), doc["root_folder"])
    # inventory_handlers.py:137-165
    item["vm_id"] = vm["instance_uuid"]
    item["vm_name"] = vm["name"]
    runtime_host = item["changeSet"]["summary"]["runtime"]["host"]
    runtime_host["uuid"] = host["uuid"]
    runtime_host["name"] = host["name"]
    item["hypervisor_os_version"] = host["version"]
    item["cluster"] = {
        **mor(doc["cluster"]["moid"], "ClusterComputeResource"),
        "name": doc["cluster"]["name"],
    }
    return item


def vds_ipfix(doc: dict) -> list[dict]:
    """stream:netflow records exported by a VDS (field names: splunk_app_stream streams/netflow)."""
    hosts = {h["name"]: h for h in doc["hosts"]}
    vds = {v["name"]: v for v in doc["vds"]}
    out = []
    for i, f in enumerate(doc["ipfix"]):
        start, end = parse(f["start"]), parse(f["end"])
        src_ip, src_port = f["src"].rsplit(":", 1)
        dst_ip, dst_port = f["dst"].rsplit(":", 1)
        event = {
            "endtime": end.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "timestamp": start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "netflow_version": 10,
            "seqnumber": 7001 + i,
            "exporter_ip": hosts[f["exporter_host"]]["vmk_ip"],
            "observation_domain_id": vds[f["vds"]]["ipfix_observation_domain_id"],
            "src_ip": src_ip,
            "dest_ip": dst_ip,
            "src_port": int(src_port),
            "dest_port": int(dst_port),
            "protoid": f["protoid"],
            "bytes": f["bytes"],
            "packets": f["packets"],
            "input_snmpidx": int(f["ingress_port_key"]),
            "output_snmpidx": int(f["egress_port_key"]),
            "src_mac": f["src_mac"],
            "dest_mac": f["dest_mac"],
        }
        out.append(
            envelope(
                epoch(end),
                "stream-fwd-01",
                "stream:netflow",
                "stream:netflow",
                "netflow",
                event,
            )
        )
    return out


def vmware_outputs(doc: dict) -> dict[str, list[dict]]:
    at = epoch(parse(doc["window"]["end"])) - 60
    vc = doc["vcenter"]
    inv = [
        envelope(
            at,
            vc,
            "VMInv:HostSystem",
            "vmware:inv:hostsystem",
            INV_INDEX,
            hostsystem(doc, h),
        )
        for h in doc["hosts"]
    ] + [
        envelope(
            at,
            vc,
            "VMInv:VirtualMachine",
            "vmware:inv:vm",
            INV_INDEX,
            virtual_machine(doc, v),
        )
        for v in doc["vms"]
    ]
    return {
        "vmware_inv.ndjson": inv,
        "vds_ipfix.ndjson": vds_ipfix(doc),
        "aci_vmm_adjacency.ndjson": aci_vmm_adjacency(doc),
        "aci_fabric_evidence.ndjson": aci_fabric_evidence(doc),
        "aci_port_channels.ndjson": aci_port_channels(doc),
    }


def aci_port_channels(doc: dict) -> list[dict]:
    """APIC pc:AggrIf and pc:RsMbrIfs for the host-facing port-channels (cisco:dc:aci:class).

    Attributes as captured live from the lab APIC through classInfo_adm (2026-11-04):
    pcAggrIf dn topology/pod-N/node-N/sys/aggr-[poN], id, name (= the access policy group,
    shared by both leaves of a vPC), pcMode; pcRsMbrIfs dn <aggr dn>/rsmbrIfs-[<tDn>],
    tDn topology/pod-N/node-N/sys/phys-[ethX/Y] and tSKey ethX/Y.
    """
    from .aci import ACI_TOPOLOGY_INPUT
    from .common import HEAVY_FORWARDER
    from .nxos import aci_event

    aci_doc = json.loads((ROOT / "fixtures" / "raw-aci" / "scenario.json").read_text())
    apic = aci_doc["fabric"]["apic"]["oob"]
    pod = aci_doc["fabric"]["pod_id"]
    switches = {s["name"]: s for s in aci_doc["fabric"]["switches"]}
    at = parse(doc["window"]["end"]) - timedelta(minutes=5)
    out = []
    for pc in doc.get("aci_port_channels", []):
        node = f"topology/pod-{pod}/node-{switches[pc['leaf']]['node_id']}"
        base = f"{node}/sys/aggr-[{pc['id']}]"
        rows = [
            (
                "pcAggrIf",
                [
                    ("dn", base),
                    ("id", pc["id"]),
                    ("name", pc["policy"]),
                    ("pcMode", "active"),
                ],
            )
        ] + [
            (
                "pcRsMbrIfs",
                [
                    ("dn", f"{base}/rsmbrIfs-[{node}/sys/phys-[{m}]]"),
                    ("tDn", f"{node}/sys/phys-[{m}]"),
                    ("tSKey", m),
                ],
            )
            for m in pc["members"]
        ]
        for component, attrs in rows:
            out.append(
                envelope(
                    epoch(at),
                    HEAVY_FORWARDER,
                    ACI_TOPOLOGY_INPUT,
                    "cisco:dc:aci:class",
                    "cisco_dc",
                    aci_event(at, attrs, apic, component),
                )
            )
    return out


def main_vmware(out_dir: Path | None = None) -> int:
    doc = json.loads((RAW_VMWARE / "scenario.json").read_text())
    for name, events in vmware_outputs(doc).items():
        print(f"{name}: {write(name, events, out_dir or RAW_VMWARE)}")
    return 0


def aci_vmm_adjacency(doc: dict) -> list[dict]:
    """APIC hvs:Adj and comp:HpNic for the ACI pilot hosts (cisco:dc:aci:class, classInfo_adm).

    Attribute names follow live APIC 6.x class output (hvsAdj addr dn ifId ifName nbrId nbrKey
    nbrName nbrType proto; compHpNic dn mac name displayName oid operSt type); the writer is the
    DC Networking classInfo path cited in fixtures/raw-aci/FIELDS.md. In this scenario the ESXi
    vmnic2 is cabled to the leaf, so the LLDP neighbor of each host is the leaf itself.
    """
    from .aci import ACI_TOPOLOGY_INPUT
    from .common import HEAVY_FORWARDER
    from .nxos import aci_event

    aci_doc = json.loads((ROOT / "fixtures" / "raw-aci" / "scenario.json").read_text())
    apic = aci_doc["fabric"]["apic"]["oob"]
    switches = {s["name"]: s for s in aci_doc["fabric"]["switches"]}
    hosts = {h["name"]: h for h in doc["hosts"]}
    ctrlr = doc["aci_vmm"]["controller_dn"]
    at = parse(doc["window"]["end"]) - timedelta(minutes=5)
    out = []
    for hv in aci_doc["hypervisors"]:
        host = hosts[hv["name"]]
        hv_dn = f"{ctrlr}/hv-{doc['aci_vmm']['hv_oids'][hv['name']]}"
        leaf = switches[hv["leaf"]]
        nic = next(p for p in host["pnics"] if p["mac"].lower() == hv["mac"].lower())
        adj = [
            ("addr", leaf["oob"]),
            ("dn", f"{hv_dn}/adj-[{leaf['oob']}]"),
            ("ifId", hv["interface"]),
            ("ifName", f"{leaf['name']} {hv['interface']}"),
            ("nbrId", doc["aci_vmm"]["leaf_chassis_mac"][leaf["name"]]),
            ("nbrKey", leaf["oob"]),
            ("nbrName", leaf["name"]),
            ("nbrType", "loosenode"),
            ("proto", "LLDP"),
            ("status", ""),
        ]
        hpnic = [
            ("displayName", nic["device"]),
            ("dn", f"{hv_dn}/hpnic-{nic['device']}"),
            ("mac", nic["mac"].upper()),
            ("name", nic["device"]),
            ("oid", f"key-vim.host.PhysicalNic-{nic['device']}"),
            ("operSt", "up"),
            ("status", ""),
            ("type", "hv"),
        ]
        for attrs, component in ((adj, "hvsAdj"), (hpnic, "compHpNic")):
            out.append(
                envelope(
                    epoch(at),
                    HEAVY_FORWARDER,
                    ACI_TOPOLOGY_INPUT,
                    "cisco:dc:aci:class",
                    "cisco_dc",
                    aci_event(at, attrs, apic, component),
                )
            )
    return out


def aci_fabric_evidence(doc: dict) -> list[dict]:
    """isis:AdjEp (leaf side) and coop:EpRec (spines) for the ACI pilot fabric.

    Attribute names follow live APIC 6.1(3g) class output (isisAdjEp dn operSt sysId type cktType
    numAdjTrans lastTrans holdExpTs; coopEpRec dn mac currCitizen pubId flags vnid vrfVnid recordTs
    lastPub remoteType). Each leaf reports one level-1 overlay adjacency per fabric uplink
    (eth1/49 -> spine-201, eth1/50 -> spine-202, sub-interface .9). Scenario fact: leaf-103's
    adjacency to spine-202 is down, so only spine-201 qualifies for leaf-103 -> leaf-102 paths.
    COOP holds a record for each VM MAC on every spine, citizen = the VM's leaf TEP.
    """
    from .aci import ACI_TOPOLOGY_INPUT
    from .common import HEAVY_FORWARDER, stable_hex, stable_int
    from .nxos import aci_event, aci_ts

    aci_doc = json.loads((ROOT / "fixtures" / "raw-aci" / "scenario.json").read_text())
    apic = aci_doc["fabric"]["apic"]["oob"]
    pod = aci_doc["fabric"]["pod_id"]
    sw = aci_doc["fabric"]["switches"]
    spines = [s for s in sw if s["role"] == "spine"]
    leaves = [s for s in sw if s["role"] == "leaf"]
    at = parse(doc["window"]["end"]) - timedelta(minutes=5)
    ts = aci_ts(at - timedelta(hours=2))
    down = {tuple(x) for x in doc["aci_fabric"]["down_adjacencies"]}
    out = []

    def emit(attrs, component):
        out.append(
            envelope(
                epoch(at),
                HEAVY_FORWARDER,
                ACI_TOPOLOGY_INPUT,
                "cisco:dc:aci:class",
                "cisco_dc",
                aci_event(at, attrs, apic, component),
            )
        )

    def sys_id(node: dict) -> str:
        h = stable_hex("isis-sysid", node["name"], length=8).upper()
        return ":".join(h[i : i + 2] for i in range(0, 8, 2)) + ":00:00"

    for leaf in leaves:
        for port, spine in zip((49, 50), spines):
            sid = sys_id(spine)
            state = "down" if (leaf["name"], spine["name"]) in down else "up"
            emit(
                [
                    ("cktType", "bcast"),
                    (
                        "dn",
                        f"topology/pod-{pod}/node-{leaf['node_id']}/sys/isis/inst-default/dom-overlay-1/if-[eth1/{port}.9]/adj-l1-adj-{sid}",
                    ),
                    ("holdExpTs", ts),
                    ("lastTrans", ts),
                    ("numAdjTrans", 1),
                    ("operSt", state),
                    ("sysId", sid),
                    ("type", "l1"),
                ],
                "isisAdjEp",
            )
    by_name = {s["name"]: s for s in sw}
    for vm in aci_doc["vms"]:
        mac = vm["mac"].upper()
        tep = by_name[vm["leaf"]]["tep"]
        vnid = 16000000 + stable_int("bd-vnid", vm["epg"], digits=6)
        for spine in spines:
            emit(
                [
                    ("currCitizen", tep),
                    (
                        "dn",
                        f"topology/pod-{pod}/node-{spine['node_id']}/sys/coop/inst/dom-overlay-1/db-ep/epr-{vnid}-epr-{mac}",
                    ),
                    ("flags", "mac-pub"),
                    ("lastPub", ts),
                    ("mac", mac),
                    ("pubId", tep),
                    ("recordTs", ts),
                    ("remoteType", "local"),
                    ("vnid", vnid),
                    ("vrfVnid", 2097153),
                ],
                "coopEpRec",
            )
    return out
