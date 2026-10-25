"""Combined campus/Meraki scenario construction and bounded output generation."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from datetime import timedelta
from datetime import timezone
from datetime import datetime
from pathlib import Path
from .common import (
    PROTO_NUMBER,
    RAW,
    RAW_ACI,
    RAW_NETWORKING,
    Scenario,
    envelope,
    epoch,
    iso_ms,
    iso_us,
    parse,
    stable_hex,
    write,
)
from .nxos import (
    nd_endpoints,
    nd_flows,
    nexus9k,
)
from .aci import (
    AciScenario,
    aci_collections,
    aci_isovalent,
    aci_kube_objects,
    aci_nd_endpoints,
    aci_nd_flows,
    aci_netflow,
    aci_otel_traces,
    hubble_flows,
    shift_iso_dates,
    shift_networking_fixed_timestamps,
)


def _networking_cluster_doc(
    template: dict, config: dict, cluster: dict, delta: timedelta
) -> dict:
    """Shift the shared ACI-shaped Cilium fixture and retain a distinct cluster identity."""
    doc = shift_iso_dates(json.loads(json.dumps(template)), int(delta.total_seconds()))
    doc["kubernetes"]["cluster"] = cluster["name"]

    trace_ids = {}
    span_ids = {}
    for trace in doc["traces"]:
        old_trace_id = trace["trace_id"]
        trace["trace_id"] = stable_hex(cluster["name"], old_trace_id, length=32)
        trace_ids[old_trace_id] = trace["trace_id"]
        for span in trace["spans"]:
            old_span_id = span["span_id"]
            span_ids[(old_trace_id, old_span_id)] = stable_hex(
                cluster["name"], old_trace_id, old_span_id, length=16
            )
    old_trace_by_new = {new: old for old, new in trace_ids.items()}
    for trace in doc["traces"]:
        old_trace_id = old_trace_by_new[trace["trace_id"]]
        for span in trace["spans"]:
            old_span_id = span["span_id"]
            old_parent = span["parent"]
            span["span_id"] = span_ids[(old_trace_id, old_span_id)]
            span["parent"] = (
                span_ids.get((old_trace_id, old_parent)) if old_parent else None
            )
    for conv in doc["conversations"]:
        conv["id"] = f"{cluster['id']}:{conv['id']}"
        for flow in conv.get("hubble", []):
            if flow.get("trace_id") in trace_ids:
                flow["trace_id"] = trace_ids[flow["trace_id"]]

    connection = next(
        item for item in config["connections"] if item["cluster_id"] == cluster["id"]
    )
    start = doc["window"]["start"]
    start_dt = parse(start) + timedelta(seconds=connection["start_offset_seconds"])
    end_dt = start_dt + timedelta(milliseconds=connection["duration_ms"])
    client = config["clients"][connection["client_id"]]
    pod = next(
        p for p in doc["kubernetes"]["pods"] if p["ip"] == connection["backend_ip"]
    )
    trace_id = stable_hex(cluster["name"], connection["id"], "trace", length=32)
    span_id = stable_hex(cluster["name"], connection["id"], "server-span", length=16)
    doc["traces"].append(
        {
            "trace_id": trace_id,
            "spans": [
                {
                    "span_id": span_id,
                    "parent": None,
                    "pod": pod["name"],
                    "service": "checkout",
                    "kind": "SPAN_KIND_SERVER",
                    "name": "GET /checkout",
                    "start": iso_ms(start_dt),
                    "end": iso_ms(end_dt),
                    "attributes": {
                        "http.request.method": "GET",
                        "http.route": "/checkout",
                        "server.port": connection["backend_port"],
                        "client.address": client["ip"],
                        "network.peer.address": client["ip"],
                    },
                }
            ],
        }
    )
    doc["conversations"].append(
        {
            "id": connection["id"],
            "summary": f"Synthetic inbound client request to {cluster['name']} checkout.",
            "transport": "tcp",
            "start": iso_ms(start_dt),
            "end": iso_ms(end_dt),
            "wire": [
                {
                    "src": f"{connection['source_ip']}:{connection['source_port']}",
                    "dst": f"{connection['destination_ip']}:{connection['destination_port']}",
                    "proto": "tcp",
                    "bytes": connection["bytes"],
                    "ingress": "leaf-102:eth1/48",
                    "egress": "leaf-102:eth1/12",
                    "nd": True,
                }
            ],
            "hubble": [
                {
                    "node": pod["node"],
                    "type": "L3_L4",
                    "point": "TO_ENDPOINT",
                    "src": f"{connection['source_ip']}:{connection['source_port']}",
                    "dst": f"{connection['backend_ip']}:{connection['backend_port']}",
                    "src_ep": "reserved:world",
                    "dst_ep": pod["name"],
                    "time": iso_ms(start_dt),
                    "syn": True,
                }
            ],
        }
    )
    return doc


def _networking_client_events(config: dict, anchor: datetime) -> dict[str, list[dict]]:
    clients = config["clients"]
    wired = clients["catalyst_wired"]
    meraki = clients["meraki_bridged_wireless"]
    at = anchor + timedelta(seconds=30)
    catalyst_event = {
        "id": wired["id"],
        "macAddress": wired["mac"],
        "ipv4Address": wired["ip"],
        "type": wired["type"],
        "connectionStatus": wired["connection_status"],
        "lastUpdatedTime": int(at.timestamp() * 1000),
        "connectedNetworkDevice": {
            "connectedNetworkDeviceName": wired["connected_device_name"],
            "connectedNetworkDeviceManagementIp": wired[
                "connected_device_management_ip"
            ],
            "connectedNetworkDeviceMac": wired["connected_device_mac"],
            "connectedNetworkDeviceType": wired["connected_device_type"],
            "interfaceName": wired["interface_name"],
        },
        "cisco_catalyst_host": wired["controller_host"],
    }
    catalyst = envelope(
        epoch(at),
        wired["connected_device_name"].lower(),
        "cisco_catalyst_dnac_client://campus_wired",
        "cisco:dnac:client",
        "cisco_catalyst",
        catalyst_event,
    )

    def association(when: datetime, ap: dict, ip: str, suffix: str = "") -> dict:
        event = {
            "occurredAt": iso_us(when),
            "networkId": meraki["network_id"],
            "type": "association",
            "description": "802.11 association",
            "category": "80211",
            "clientId": meraki["client_id"],
            "clientDescription": meraki["description"],
            "clientMac": meraki["mac"],
            "deviceSerial": ap["serial"],
            "deviceName": ap["name"],
            "ssidNumber": meraki["ssid_number"],
            "eventData": {
                "radio": "1",
                "vap": "1",
                "client_mac": meraki["mac"],
                "client_ip": ip,
                "channel": "36",
                "rssi": "12",
                "aid": "2104009183",
            },
            "organizationId": meraki["organization_id"],
        }
        return envelope(
            epoch(when),
            ap["name"].lower(),
            "cisco_meraki_accesspoints::networking_wireless",
            "meraki:accesspoints",
            "cisco_meraki",
            event,
        )

    ap1, ap2 = meraki["access_points"]
    assoc_one_time = anchor + timedelta(seconds=60)
    assoc_roam_time = anchor + timedelta(seconds=150)
    associations = [
        association(assoc_one_time, ap1, meraki["ip"]),
        # Cisco's current API example documents type=association. Sequential association
        # observations model a roam without inventing a disassociation event.
        association(assoc_roam_time, ap2, meraki["ip"]),
    ]
    # DHCP/IP reuse: a second client identity is observed with the old address later.
    reused = dict(meraki)
    reused.update(
        {
            "client_id": "demo-client-71-21",
            "mac": "02:71:00:00:00:21",
            "description": "Synthetic second wireless client",
        }
    )
    associations.append(association(anchor + timedelta(seconds=240), ap1, meraki["ip"]))
    reuse_event = associations[-1]["event"]
    reuse_event["clientId"] = reused["client_id"]
    reuse_event["clientDescription"] = reused["description"]
    reuse_event["clientMac"] = reused["mac"]
    reuse_event["eventData"]["client_mac"] = reused["mac"]

    # Two simultaneous claims for a separate MAC intentionally conflict. Both use the
    # documented association event shape; neither is used by a positive flow example.
    conflict_mac = "02:71:00:00:00:22"
    for ap, ip in ((ap1, "10.71.0.22"), (ap2, "10.71.0.23")):
        conflict = association(anchor + timedelta(seconds=80), ap, ip)
        conflict["event"]["clientId"] = "demo-client-conflict"
        conflict["event"]["clientMac"] = conflict_mac
        conflict["event"]["eventData"]["client_mac"] = conflict_mac
        conflict["event"]["eventData"]["client_ip"] = ip
        associations.append(conflict)

    # An old association and an unassociated flow are negative evidence only.
    stale = association(anchor - timedelta(hours=1), ap1, "10.71.0.88")
    stale["event"]["clientId"] = "demo-client-stale"
    stale["event"]["clientMac"] = "02:71:00:00:00:88"
    stale["event"]["eventData"]["client_mac"] = "02:71:00:00:00:88"
    associations.append(stale)
    associations.append(json.loads(json.dumps(associations[0])))

    inventory = []
    for ap in meraki["access_points"]:
        item = {
            "name": ap["name"],
            "networkId": meraki["network_id"],
            "serial": ap["serial"],
            "model": ap["model"],
            "mac": ap["mac"],
            "lanIp": ap["lan_ip"],
            "productType": "wireless",
            "organizationId": meraki["organization_id"],
        }
        inventory.append(
            envelope(
                epoch(anchor),
                ap["name"].lower(),
                "cisco_meraki_devices::networking_inventory",
                "meraki:devices",
                "cisco_meraki",
                item,
            )
        )

    switch = meraki["switch"]
    inventory.append(
        envelope(
            epoch(anchor),
            switch["name"].lower(),
            "cisco_meraki_devices::networking_inventory",
            "meraki:devices",
            "cisco_meraki",
            {
                "name": switch["name"],
                "networkId": meraki["network_id"],
                "serial": switch["serial"],
                "model": switch["model"],
                "mac": switch["mac"],
                "productType": "switch",
                "organizationId": meraki["organization_id"],
            },
        )
    )
    topology = {
        "name": switch["name"],
        "serial": switch["serial"],
        "mac": switch["mac"],
        "network": {"name": "Demo Network", "id": meraki["network_id"]},
        "model": switch["model"],
        "ports": [
            {
                "portId": switch["port_id"],
                "lastUpdatedAt": iso_ms(anchor),
                "lldp": [
                    {"name": "System name", "value": switch["lldp_neighbor_name"]}
                ],
            },
            {
                "portId": "11",
                "lastUpdatedAt": iso_ms(anchor),
                "lldp": [{"name": "System name", "value": ap2["name"]}],
            },
        ],
        "organizationId": meraki["organization_id"],
        "endpoint_name": "switch_ports_topology_discovery_by_device",
        "endpoint_path": "/organizations/{organizationId}/switch/ports/topology/discovery/byDevice",
        "operation_id": "getOrganizationSwitchPortsTopologyDiscoveryByDevice",
        "collection_time": iso_ms(anchor),
    }
    topology_event = envelope(
        epoch(anchor),
        switch["name"].lower(),
        "cisco_meraki_custom_api::networking_switch_topology",
        "meraki:custom",
        "cisco_meraki",
        topology,
    )
    return {
        "catalyst_clients.ndjson": [catalyst],
        "meraki_associations.ndjson": associations,
        "meraki_inventory.ndjson": inventory,
        "meraki_topology.ndjson": [topology_event],
    }


def _networking_flow_events(config: dict, anchor: datetime) -> dict[str, list[dict]]:
    events = {
        "campus_netflow.ndjson": [],
        "sdwan_netflow.ndjson": [],
        "meraki_ms390_ipfix.ndjson": [],
    }
    wired = config["clients"]["catalyst_wired"]
    for connection in config["connections"]:
        start = anchor + timedelta(seconds=connection["start_offset_seconds"])
        end = start + timedelta(milliseconds=connection["duration_ms"])
        is_sdwan = connection["cluster_id"] == "aci"
        event = {
            "timestamp": iso_us(start),
            "endtime": iso_us(end),
            "netflow_version": 10,
            "src_ip": connection["source_ip"],
            "dest_ip": connection["destination_ip"],
            "src_port": connection["source_port"],
            "dest_port": connection["destination_port"],
            "protoid": PROTO_NUMBER["tcp"],
            "bytes": connection["bytes"],
            "packets": connection["packets"],
            "tcp_flags": connection["tcp_flags"],
        }
        if is_sdwan:
            sdwan = connection["sdwan"]
            event.update(
                {
                    "exporter_ip": sdwan["exporter_ip"],
                    "observation_domain_id": sdwan["observation_domain_id"],
                    "flow_id": sdwan["flow_id"],
                    "flow_start_time_milli": int(epoch(start) * 1000),
                    "flow_end_time_milli": int(epoch(end) * 1000),
                    "vpn_id": sdwan["vpn_id"],
                    "ingress_overlay_session_id": sdwan["ingress_overlay_session_id"],
                    "egress_overlay_session_id": sdwan["egress_overlay_session_id"],
                }
            )
            dest = "sdwan_netflow.ndjson"
            host = "sdwan-edge-01"
            campus_fields = {
                key: value
                for key, value in event.items()
                if key
                in {
                    "timestamp",
                    "endtime",
                    "netflow_version",
                    "src_ip",
                    "dest_ip",
                    "src_port",
                    "dest_port",
                    "protoid",
                    "bytes",
                    "packets",
                    "tcp_flags",
                }
            }
            campus_fields["exporter_ip"] = wired["campus_fnf_exporter_ip"]
            campus_fields["observation_domain_id"] = wired[
                "campus_fnf_observation_domain_id"
            ]
            events["campus_netflow.ndjson"].append(
                envelope(
                    epoch(end),
                    "stream-fwd-campus",
                    "stream:netflow",
                    "stream:netflow",
                    "netflow",
                    campus_fields,
                )
            )
        else:
            client = config["clients"][connection["client_id"]]
            event["src_mac"] = client["mac"]
            event["exporter_ip"] = client["switch"]["exporter_ip"]
            event["observation_domain_id"] = client["switch"]["observation_domain_id"]
            dest = "meraki_ms390_ipfix.ndjson"
            host = "stream-fwd-ms390"
        events[dest].append(
            envelope(
                epoch(end),
                host,
                "stream:netflow",
                "stream:netflow",
                "netflow",
                event,
            )
        )

    # A source-only flow demonstrates missing association and exporter enrichment. Its
    # documented standard fields are present; MAC/sampling/direction and NAT context are not.
    unknown_start = anchor + timedelta(seconds=300)
    unknown_event = {
        "timestamp": iso_us(unknown_start),
        "endtime": iso_us(unknown_start + timedelta(milliseconds=100)),
        "netflow_version": 10,
        "src_ip": "10.71.0.99",
        "dest_ip": "10.50.0.20",
        "src_port": 55399,
        "dest_port": 8080,
        "protoid": PROTO_NUMBER["tcp"],
        "bytes": 720,
        "packets": 3,
    }
    events["meraki_ms390_ipfix.ndjson"].append(
        envelope(
            epoch(unknown_start + timedelta(milliseconds=100)),
            "stream-fwd-ms390",
            "stream:netflow",
            "stream:netflow",
            "netflow",
            unknown_event,
        )
    )
    # IP reuse is observed at a later event time. The source MAC makes the second client
    # explicit in this record; the separate association event supplies its AP identity.
    reuse_start = anchor + timedelta(seconds=270)
    reuse_event = {
        "timestamp": iso_us(reuse_start),
        "endtime": iso_us(reuse_start + timedelta(milliseconds=110)),
        "netflow_version": 10,
        "src_ip": "10.71.0.20",
        "dest_ip": "10.50.0.20",
        "src_port": 55221,
        "dest_port": 8080,
        "protoid": PROTO_NUMBER["tcp"],
        "bytes": 860,
        "packets": 3,
        "src_mac": config["clients"]["meraki_bridged_wireless"]["mac"],
        "exporter_ip": config["clients"]["meraki_bridged_wireless"]["switch"][
            "exporter_ip"
        ],
        "observation_domain_id": config["clients"]["meraki_bridged_wireless"]["switch"][
            "observation_domain_id"
        ],
    }
    # The second client MAC is the one in the later association payload.
    reuse_event["src_mac"] = "02:71:00:00:00:21"
    events["meraki_ms390_ipfix.ndjson"].append(
        envelope(
            epoch(reuse_start + timedelta(milliseconds=110)),
            "stream-fwd-ms390",
            "stream:netflow",
            "stream:netflow",
            "netflow",
            reuse_event,
        )
    )
    return events


def _networking_fabric_events(
    config: dict, template: dict, anchor: datetime, delta: timedelta
) -> dict[str, list[dict]]:
    """Build ACI and NX-OS evidence using the existing TA-grounded generators."""
    outputs: dict[str, list[dict]] = {}
    aci_doc = _networking_cluster_doc(
        template,
        config,
        next(cluster for cluster in config["clusters"] if cluster["id"] == "aci"),
        delta,
    )
    aci_scenario = AciScenario(aci_doc)
    outputs["aci_stats.ndjson"], outputs["aci_class.ndjson"] = aci_collections(
        aci_scenario, timestamp_delta=delta
    )
    outputs["aci_netflow.ndjson"] = aci_netflow(aci_scenario)
    outputs["aci_nd_flows.ndjson"] = aci_nd_flows(aci_scenario)
    outputs["aci_nd_endpoints.ndjson"] = aci_nd_endpoints(
        aci_scenario, created_at=anchor
    )

    nxos_doc = shift_iso_dates(
        json.loads((RAW / "scenario.json").read_text()), int(delta.total_seconds())
    )
    nxos_cluster = next(
        cluster for cluster in config["clusters"] if cluster["id"] == "nxos"
    )
    nxos_app_doc = _networking_cluster_doc(template, config, nxos_cluster, delta)
    nxos_doc["kubernetes"] = nxos_app_doc["kubernetes"]
    nxos_doc["window"] = nxos_app_doc["window"]
    nxos_doc["nexus_dashboard"]["host"] = "10.71.255.60"
    nxos_doc["nexus_dashboard"]["fabric"] = nxos_cluster["fabric"]
    nxos_doc["aci"] = {"endpoints": []}
    connection = next(
        item for item in config["connections"] if item["cluster_id"] == "nxos"
    )
    start = anchor + timedelta(seconds=connection["start_offset_seconds"])
    end = start + timedelta(milliseconds=connection["duration_ms"])
    nxos_doc["conversations"] = [
        {
            "id": connection["id"],
            "client": f"{connection['source_ip']}:{connection['source_port']}",
            # Nexus Dashboard observes the pre-DNAT fabric tuple: the external
            # client targets the LoadBalancer VIP. Hubble separately records
            # the translated client-to-pod tuple. Do not synthesize a post-NAT
            # reverse mapping into the fabric observation.
            "server": f"{connection['destination_ip']}:{connection['destination_port']}",
            "bytes_c2s": connection["bytes"],
            "bytes_s2c": connection["bytes"],
            "transport": "tcp",
            "start": iso_ms(start),
            "end": iso_ms(end),
            "seen_by": ["nd"],
        }
    ]
    nxos_scenario = Scenario(nxos_doc)
    outputs["nxos_inventory.ndjson"] = nexus9k(nxos_scenario)
    outputs["nxos_nd_flows.ndjson"] = nd_flows(nxos_scenario)
    outputs["nxos_nd_endpoints.ndjson"] = nd_endpoints(nxos_scenario)
    return outputs


def main_networking(base_time: str | None = None, output_dir: str | None = None) -> int:
    config = json.loads((RAW_NETWORKING / "scenario.json").read_text())
    template = json.loads((RAW_ACI / "scenario.json").read_text())
    anchor = (
        parse(base_time)
        if base_time
        else datetime.now(timezone.utc).replace(microsecond=0)
    )
    original_start = parse(template["window"]["start"])
    delta = anchor - original_start
    outputs = _networking_client_events(config, anchor)
    outputs.update(_networking_flow_events(config, anchor))
    outputs.update(_networking_fabric_events(config, template, anchor, delta))
    cluster_docs = []
    for cluster in config["clusters"]:
        doc = _networking_cluster_doc(template, config, cluster, delta)
        cluster_docs.append(AciScenario(doc))
    outputs["kube_objects.ndjson"] = [
        event
        for scenario in cluster_docs
        for event in aci_kube_objects(scenario, created_at=anchor)
    ]
    outputs["hubble_flows.ndjson"] = [
        event for scenario in cluster_docs for event in hubble_flows(scenario)
    ]
    outputs["isovalent.ndjson"] = [
        event
        for scenario, cluster in zip(cluster_docs, config["clusters"], strict=True)
        for event in aci_isovalent(
            scenario,
            hec_source=(
                "http:isovalent-aci"
                if cluster["id"] == "aci"
                else "http:isovalent-nxos"
            ),
        )
    ]
    outputs["otel_traces.ndjson"] = [
        event for scenario in cluster_docs for event in aci_otel_traces(scenario)
    ]
    for events in outputs.values():
        for event in events:
            if "event" in event:
                event["event"] = shift_networking_fixed_timestamps(
                    event["event"], delta
                )
    output_path = (
        Path(output_dir).expanduser().resolve() if output_dir else RAW_NETWORKING
    )
    output_path.mkdir(parents=True, exist_ok=True)
    for input_name in ("scenario.json", "source-profiles.json", "FIELDS.md"):
        (output_path / input_name).write_text((RAW_NETWORKING / input_name).read_text())
    event_counts = {}
    index_counts: Counter[str] = Counter()
    sourcetype_counts: Counter[str] = Counter()
    hec_times = []
    for name, events in outputs.items():
        print(f"{name}: {write(name, events, output_path)}")
        event_counts[name] = len(events)
        index_counts.update(event["index"] for event in events)
        sourcetype_counts.update(event["sourcetype"] for event in events)
        hec_times.extend(event["time"] for event in events)
    graph_start = anchor
    graph_end = parse(template["window"]["end"]) + delta
    manifest = {
        "scenario_id": config["scenario_id"],
        "fixture_kind": "synthetic_raw_only",
        "base_time": iso_ms(anchor),
        "graph_window": {
            "start": iso_ms(graph_start),
            "end": iso_ms(graph_end),
            "description": "Intended 15-minute scenario window; this is distinct from the wider HEC ingestion range.",
        },
        "ingestion_window": {
            "start": iso_ms(datetime.fromtimestamp(min(hec_times), timezone.utc)),
            "end": iso_ms(datetime.fromtimestamp(max(hec_times), timezone.utc)),
            "basis": "Minimum and maximum HEC event time across every generated raw file, including deliberately stale and inventory records.",
        },
        "window_start": iso_ms(graph_start),
        "window_end": iso_ms(graph_end),
        "source_profiles": {
            "file": "source-profiles.json",
            "sha256": hashlib.sha256(
                (output_path / "source-profiles.json").read_bytes()
            ).hexdigest(),
        },
        "output_events": event_counts,
        "index_events": dict(sorted(index_counts.items())),
        "sourcetype_events": dict(sorted(sourcetype_counts.items())),
        "qualification": "Synthetic TA-shaped fixture; no API collection, exporter template decoding, or live attachment is asserted.",
    }
    (output_path / "capture-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )
    print(f"capture-manifest.json: {len(event_counts)} output files")
    return 0
