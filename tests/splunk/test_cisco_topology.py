"""Checks for the source-qualified topology v2 macro.

The static check reads the committed app macro after integration. During review, it
can read the ignored proposal from dist. The opt-in runtime check uses an already
initialized lab and never starts, resets, or loads it.
"""

from __future__ import annotations

import json
import hashlib
import os
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MACRO_PATH = ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"
PROPOSAL_PATH = ROOT / "dist" / "cisco-topology-v2.conf"
FIXTURE_DIR = ROOT / "fixtures" / "raw-networking"
DEFAULT_INITIALIZATION = ROOT / "dist" / "networking-path-tests" / "initialization.json"


def extract_macro(text: str, name: str) -> str:
    """Return one complete Splunk macro stanza, excluding following stanzas."""
    import re

    match = re.search(rf"(?ms)^\[{re.escape(name)}\]\n.*?(?=^\[|\Z)", text)
    return match.group(0) if match else ""


class TopologyV2ProposalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_macros = MACRO_PATH.read_text("utf-8")
        cls.text = extract_macro(app_macros, "adm_topology_v2")
        if not cls.text and PROPOSAL_PATH.exists():
            cls.text = extract_macro(
                PROPOSAL_PATH.read_text("utf-8"), "adm_topology_v2"
            )

    def test_inventory_lookback_clamps_at_epoch_zero(self):
        bounds = extract_macro(
            MACRO_PATH.read_text("utf-8"), "adm_topology_inventory_time_bounds"
        )
        self.assertIn(
            "earliest=max(0,info_min_time-`adm_topology_inventory_lookback_seconds`)",
            bounds,
        )

    def test_macro_contract_is_staged_and_no_args(self):
        self.assertRegex(self.text, r"(?m)^\[adm_topology_v2\]$")
        self.assertNotRegex(self.text, r"(?m)^\[adm_topology_v2\(\d+\)\]$")
        self.assertIn('row_type="device"', self.text)
        self.assertIn('row_type="link"', self.text)
        self.assertIn('link_kind="physical"', self.text)
        self.assertIn("wireless_association", self.text)
        self.assertIn("device_authority", self.text)
        self.assertIn("native_device_id", self.text)
        self.assertIn("mapping_status", self.text)
        self.assertIn("proc_board_id", self.text)
        self.assertIn('adm_scope_kind="nxos_serial"', self.text)
        self.assertIn('device_kind="host"', self.text)
        self.assertIn('device_kind="network_client"', self.text)
        self.assertNotIn('device_id="sdwan_router:"', self.text)
        self.assertIn("adm_qualified_devices", self.text)
        self.assertIn("adm_mv_has(adm_qualified_devices,adm_a_key)", self.text)
        self.assertIn("adm_mv_has(adm_qualified_devices,adm_b_key)", self.text)

    def test_observer_scope_keys_match_the_lowercase_writer(self):
        # adm_observer_scope is case-sensitive and every writer lowercases
        # observer_kind/observer (savedsearches.conf "ADM - Migrate observer scope").
        import re

        kinds = re.findall(r'adm_(?:local_|peer_)?scope_kind="([^"]*)"', self.text)
        self.assertTrue(kinds)
        self.assertEqual([kind for kind in kinds if kind != kind.lower()], [])
        observers = re.findall(
            r"adm_(?:local_|peer_)?scope_observer=([^,\\\s]+)", self.text
        )
        self.assertGreaterEqual(len(observers), 11)
        self.assertEqual(
            [value for value in observers if not value.startswith("lower(")], []
        )

    def test_history_generators_have_a_pipeline_context_in_subsearches(self):
        self.assertEqual(
            self.text.count("| append [ | `adm_network_client_history_observations`"),
            3,
        )

    def test_meraki_association_and_inventory_share_one_collision_safe_device_key(self):
        macros = (
            ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"
        ).read_text("utf-8")
        history = extract_macro(macros, "adm_network_client_history_observations")
        device_id = '"meraki:".sha256(json_array("meraki_device", tostring(coalesce(organizationId,"")), tostring(coalesce(networkId,""))'
        self.assertIn(device_id + ", tostring(deviceSerial)))", history)
        self.assertIn(device_id + ', tostring(coalesce(serial,""))))', self.text)
        self.assertIn(device_id + ", tostring(adm_local_serial)))", self.text)
        self.assertIn(device_id + ", tostring(adm_peer_serial)))", self.text)

    def test_legacy_topology_is_not_replaced_and_no_flow_adjacency(self):
        macros = (
            ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"
        ).read_text("utf-8")
        self.assertIn("[adm_topology]", macros)
        self.assertNotIn('link_kind="traffic_observation"', self.text)
        self.assertNotRegex(self.text, r"(?i)scope=\"default\"")
        self.assertNotRegex(self.text, r"(?i)join\s+type=.*max\s*=\s*1")
        self.assertNotRegex(self.text, r"(?i)^\s*\|\s*dedup\b")
        self.assertNotIn("event.ports", self.text)
        self.assertIn(
            'endpoint_name="switch_ports_topology_discovery_by_device"', self.text
        )
        self.assertIn("adm_peer_count==1", self.text)

    def test_raw_fixture_inputs_match_the_staged_source_contract(self):
        aci = (FIXTURE_DIR / "aci_class.ndjson").read_text("utf-8")
        nxos = (FIXTURE_DIR / "nxos_inventory.ndjson").read_text("utf-8")
        meraki_devices = (FIXTURE_DIR / "meraki_inventory.ndjson").read_text("utf-8")
        associations = (FIXTURE_DIR / "meraki_associations.ndjson").read_text("utf-8")
        for field in ("apic_host", "topSystem", "fabricLink", "n1", "n2"):
            self.assertIn(field, aci)
        for field in (
            "nxhostname",
            "nxversion",
            "proc_board_id",
            "nxneighbor",
            "v4mgmtaddr",
            "intf_id",
            "port_id",
        ):
            self.assertIn(field, nxos)
        for field in ("organizationId", "networkId", "serial", "productType"):
            self.assertIn(field, meraki_devices)
        for field in (
            "occurredAt",
            "association",
            "clientMac",
            "deviceSerial",
            "ssidNumber",
        ):
            self.assertIn(field, associations)
        topology_rows = [
            json.loads(line)
            for line in (FIXTURE_DIR / "meraki_topology.ndjson")
            .read_text("utf-8")
            .splitlines()
        ]
        topology_event = topology_rows[0]["event"]
        self.assertIn("ports", topology_event)
        self.assertIn("network", topology_event)
        self.assertNotIn("event", topology_event)
        version_events = []
        for line in nxos.splitlines():
            raw = json.loads(json.loads(line)["event"])
            if raw.get("component") == "nxversion":
                version_events.append(raw)
        self.assertTrue(version_events)
        self.assertTrue(
            all("proc_board_id" in event["Row_info"][0] for event in version_events)
        )

    def test_nxos_authority_is_explicit_and_qualified(self):
        profiles = json.loads((FIXTURE_DIR / "source-profiles.json").read_text("utf-8"))
        mappings = profiles["legacy_observer_scope"]
        serial_maps = [row for row in mappings if row["observer_kind"] == "nxos_serial"]
        self.assertEqual(len(serial_maps), 3)
        for row in serial_maps:
            parts = json.loads(row["observer"])
            self.assertEqual(len(parts), 2)
            self.assertEqual(parts[0], "splunk-hf-01")
            self.assertRegex(parts[1], r"^fdo24411[a-c]{3}$")

    def test_nxos_fabric_tuple_is_pre_dnat_vip_and_not_backend(self):
        nd_rows = [
            json.loads(line)
            for line in (FIXTURE_DIR / "nxos_nd_flows.ndjson")
            .read_text("utf-8")
            .splitlines()
        ]
        flow = next(
            json.loads(row["event"]) for row in nd_rows if "10.71.0.20" in row["event"]
        )
        self.assertEqual(flow["dstIp"], "10.50.0.20")
        self.assertEqual(flow["dstPort"], 8080)
        self.assertNotEqual(flow["dstIp"], "10.42.1.20")

    def test_repeated_kubernetes_host_names_and_ips_remain_cluster_qualified(self):
        nodes = []
        for line in (
            (FIXTURE_DIR / "kube_objects.ndjson").read_text("utf-8").splitlines()
        ):
            hec = json.loads(line)
            if hec.get("sourcetype") != "kube:object:nodes":
                continue
            node = hec["event"]["object"]
            if node["metadata"]["name"] != "node-b":
                continue
            nodes.append((hec["fields"]["k8s.cluster.name"], node))
        clusters = {cluster for cluster, _ in nodes}
        self.assertEqual(clusters, {"cilium-aci-east", "cilium-nxos-west"})
        self.assertEqual(len({node["metadata"]["uid"] for _, node in nodes}), 1)
        ids = {
            hashlib.sha256(
                json.dumps(
                    ["kubernetes_node", cluster, node["metadata"]["uid"]],
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            for cluster, node in nodes
        }
        self.assertEqual(len(ids), 2)

    def test_nxos_cdp_requires_unique_identity_and_same_scope(self):
        self.assertIn("| join type=inner max=0 host adm_local_endpoint", self.text)
        self.assertIn("adm_local_serial_count==1", self.text)
        self.assertIn("adm_peer_scope_count==1", self.text)
        self.assertIn("adm_local_scope==adm_peer_scope", self.text)
        self.assertIn("adm_local_cluster==adm_peer_cluster", self.text)
        self.assertIn("replace('Row_info.device_id'", self.text)

    def test_supported_inventory_keeps_qualified_aliases_and_interfaces(self):
        for field in ("aliases", "aci_node", "role", "fabric", "os_version"):
            self.assertIn(field, self.text)
        self.assertIn("aci_node=native_device_id", self.text)
        self.assertIn('component="nxhostname"', self.text)
        self.assertIn('component="nxinterface"', self.text)
        self.assertIn('row_type="interface"', self.text)
        self.assertIn("adm_native_count==1", self.text)
        self.assertIn("ifindex=if(mvcount(adm_ifindex_values)==1", self.text)
        self.assertIn("host=lower(host)", self.text)

    def test_host_lldp_and_firewall_inventory_are_scoped(self):
        self.assertIn('component="lldpAdjEp"', self.text)
        self.assertIn("join type=left max=0 scope cluster sysName", self.text)
        self.assertIn("adm_host_count==1", self.text)
        self.assertIn(
            '"host:".sha256(json_array("kubernetes_node",cluster,adm_host_uid))',
            self.text,
        )
        self.assertIn('adm_scope_kind="firewall"', self.text)
        self.assertIn('device_kind="firewall"', self.text)
        self.assertIn("those attachments remain unresolved", self.text)

    def test_catalyst_switch_port_belongs_to_attachment_device(self):
        self.assertIn(
            "b_device_name=attachment_device_name, a_interface=null(), b_interface=interface",
            self.text,
        )

    def test_sdwan_flow_references_do_not_invent_tloc_inventory_or_route_links(self):
        profiles = json.loads((FIXTURE_DIR / "source-profiles.json").read_text("utf-8"))
        sdwan = [
            row
            for row in profiles["network_source_scope"]
            if row["profile"] == "catalyst_sdwan_ipfix"
        ]
        self.assertEqual(len(sdwan), 1)
        self.assertNotIn("tloc_local_system_ip", self.text)
        self.assertNotIn("tloc_remote_system_ip", self.text)
        self.assertNotIn('evidence_kind="observed_overlay_context"', self.text)
        self.assertNotIn('link_kind="overlay_context"', self.text)
        self.assertIn("do not create topology adjacency", self.text)

    def test_fixture_manifest_has_bounded_ingestion_range(self):
        manifest = json.loads(
            (FIXTURE_DIR / "capture-manifest.json").read_text("utf-8")
        )
        start = datetime.fromisoformat(
            manifest["ingestion_window"]["start"].replace("Z", "+00:00")
        )
        end = datetime.fromisoformat(
            manifest["ingestion_window"]["end"].replace("Z", "+00:00")
        )
        self.assertLess(start, end)
        self.assertEqual(manifest["scenario_id"], "campus-meraki-two-cluster")


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1",
    "requires installed Splunk lab and preloaded raw-networking fixtures",
)
class TopologyV2LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys_path = str(Path(__file__).resolve().parent)
        import sys

        if sys_path not in sys.path:
            sys.path.insert(0, sys_path)
        import lab

        cls.lab = lab
        initialization_path = Path(
            os.environ.get("ADM_NETWORKING_INITIALIZATION", str(DEFAULT_INITIALIZATION))
        )
        if not initialization_path.is_absolute():
            initialization_path = ROOT / initialization_path
        initialized = json.loads(initialization_path.read_text("utf-8"))
        earliest = os.environ.get("ADM_NETWORKING_WINDOW_START")
        latest = os.environ.get("ADM_NETWORKING_WINDOW_END")
        if (earliest is None) != (latest is None):
            raise ValueError(
                "set both ADM_NETWORKING_WINDOW_START and ADM_NETWORKING_WINDOW_END"
            )
        cls.window = (
            (earliest, latest)
            if earliest is not None and latest is not None
            else (initialized["window"]["earliest"], initialized["window"]["latest"])
        )
        cls.rows = lab.search("| search `adm_topology_v2`", *cls.window)

    def test_source_qualified_devices_and_typed_links(self):
        devices = [row for row in self.rows if row.get("row_type") == "device"]
        links = [row for row in self.rows if row.get("row_type") == "link"]
        ids = [row.get("device_id", "") for row in devices]
        self.assertTrue(any(value.startswith("aci:") for value in ids))
        self.assertTrue(any(value.startswith("nxos:") for value in ids))
        self.assertTrue(any(value.startswith("meraki:") for value in ids))
        self.assertTrue(
            all(
                row.get("link_kind") in {"physical", "wireless_association"}
                for row in links
            )
        )
        self.assertTrue(
            any(row.get("link_kind") == "wireless_association" for row in links)
        )
        self.assertTrue(
            all(row.get("a_device") and row.get("b_device") for row in links)
        )
        # The fixture intentionally repeats Cilium service/device display names across clusters;
        # topology IDs must remain source-qualified and distinct.
        self.assertEqual(len(ids), len(set(ids)))

    def test_both_meraki_ap_uplinks_match_source_qualified_inventory(self):
        import sys

        sys.path.insert(0, str(ROOT / "tools"))
        from capture_networking_fixtures import require_topology

        require_topology(self.rows)

    def test_catalyst_switch_port_is_on_the_switch_end_of_the_link(self):
        links = [
            row
            for row in self.rows
            if row.get("row_type") == "link"
            and row.get("link_source") == "catalyst_client_snapshot"
        ]
        self.assertEqual(len(links), 1)
        link = links[0]
        devices = {
            row["device_id"]: row
            for row in self.rows
            if row.get("row_type") == "device"
        }
        self.assertTrue(link["a_device"].startswith("network_client:"))
        self.assertEqual(devices[link["a_device"]]["device_kind"], "network_client")
        self.assertEqual(devices[link["b_device"]]["device_kind"], "switch")
        self.assertEqual(devices[link["b_device"]]["name"], "CAMPUS-SW-01")
        self.assertFalse(link.get("a_interface"))
        self.assertEqual(link["b_interface"], "GigabitEthernet1/0/24")
        self.assertEqual(link["link_kind"], "physical")
        self.assertEqual(link["scope"], "campus-aci")

    def test_inventory_preserves_aci_and_nxos_resolution_fields(self):
        devices = [row for row in self.rows if row.get("row_type") == "device"]
        aci = [row for row in devices if row.get("device_id", "").startswith("aci:")]
        nxos = [row for row in devices if row.get("device_id", "").startswith("nxos:")]
        self.assertTrue(aci)
        self.assertTrue(nxos)
        for row in aci:
            self.assertRegex(row.get("aci_node", ""), r"^pod-\d+/node-\d+$")
            self.assertIn(row.get("role"), {"leaf", "spine", "controller"})
            self.assertEqual(row.get("mapping_status"), "mapped")
            self.assertTrue(row.get("aliases"))
        self.assertEqual(
            {row.get("name") for row in nxos}, {"leaf-101", "leaf-102", "border-1"}
        )
        self.assertTrue(
            all(row.get("serial") and row.get("os_version") for row in nxos)
        )
        ids = {row["device_id"] for row in nxos}
        interfaces = [row for row in self.rows if row.get("row_type") == "interface"]
        self.assertTrue(interfaces)
        self.assertTrue(all(row.get("device_id") in ids for row in interfaces))
        self.assertTrue(all(row.get("scope") == "meraki-nxos" for row in interfaces))
        # Only CDP records carrying an actual ifIndex may supply a mapping.
        expected_indexes = set()
        by_ip = {row["mgmt_ip"]: row["device_id"] for row in nxos}
        for line in (FIXTURE_DIR / "nxos_inventory.ndjson").read_text().splitlines():
            event = json.loads(json.loads(line)["event"])
            port = event.get("Row_info")
            if (
                event.get("component") == "nxneighbor"
                and isinstance(port, dict)
                and port.get("ifindex") is not None
            ):
                expected_indexes.add(
                    (
                        by_ip[event["device"].rsplit(":", 1)[0]],
                        port["intf_id"],
                        str(port["ifindex"]),
                    )
                )
        self.assertEqual(
            {
                (row["device_id"], row["interface"], str(row["ifindex"]))
                for row in interfaces
                if row.get("ifindex")
            },
            expected_indexes,
        )


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class TopologyV2MixedCaseScopeLabTest(unittest.TestCase):
    """Mixed-case source authorities must match lowercase-keyed scope rows.

    Clones are indexed 20 days in the past so they stay outside the
    wall-clock-anchored fixture windows used by the other topology tests.
    """

    @classmethod
    def setUpClass(cls):
        import sys
        import time
        import urllib.parse
        import uuid

        sys.path.insert(0, str(ROOT / "tools"))
        sys.path.insert(0, str(ROOT / "tests" / "splunk"))
        from lab_lock import LabLock

        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")
        import lab

        cls.lab = lab
        token = uuid.uuid4().hex[:8]
        cls.apic = f"APIC-{token.upper()}.Example"
        cls.organization = f"ORG-{token.upper()}"
        cls.network = f"N_{token.upper()}Mixed"
        cls.meraki_authority = json.dumps(
            [cls.organization, cls.network], separators=(",", ":")
        )
        cls.cluster = f"Cilium-{token.upper()}-East"
        cls.scope = f"Mixed-Case-{token}"
        anchor = int(time.time()) - 20 * 86400
        cls.window = (str(anchor - 60), str(anchor + 60))

        query = urllib.parse.urlencode({"query": json.dumps({"scope": cls.scope})})
        cls.cleanup_path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            "adm_observer_scope?" + query
        )
        # Mirrors the shipped writer: matching keys lowercased, values unchanged.
        mappings = [
            {"observer_kind": "apic", "observer": cls.apic},
            {"observer_kind": "network_authority", "observer": cls.meraki_authority},
            {"observer_kind": "cluster", "observer": cls.cluster},
        ]
        rows = [{**row, "scope": cls.scope, "cluster": cls.cluster} for row in mappings]
        data = json.dumps(json.dumps(rows, separators=(",", ":")))
        try:
            lab.search(
                f"| makeresults format=json data={data} "
                "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
                'cluster=coalesce(cluster, ""), _key=sha256(json_array(observer_kind, observer)) '
                "| fields _key observer_kind observer scope cluster "
                "| outputlookup append=true key_field=_key override_if_empty=false adm_observer_scope",
                "0",
                str(int(time.time()) + 3600),
            )
            stored = lab.search(
                "| inputlookup adm_observer_scope "
                f"| where scope={json.dumps(cls.scope)} "
                "| table observer_kind observer",
                "0",
                str(int(time.time()) + 3600),
            )
            if sorted(row["observer"] for row in stored) != sorted(
                row["observer"].lower() for row in mappings
            ):
                raise RuntimeError("mixed-case scope rows were not stored lowercase")
            cls._load_events(token, anchor)
            cls.rows = lab.search("| search `adm_topology_v2`", *cls.window)
        finally:
            lab._mgmt("DELETE", cls.cleanup_path).close()

    @classmethod
    def _load_events(cls, token: str, anchor: int):
        import tempfile
        import time

        aci = (
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(anchor))}"
            '\taddress=10.0.200.91\tdn="topology/pod-1/node-901/sys"\tfabricId=1'
            '\tinbMgmtAddr=0.0.0.0\tname="leaf-mixed-901"\toobMgmtAddr=192.0.2.91'
            '\tpodId=1\trole="leaf"\tserial="FDOMIXED901"\tstate="in-service"'
            f"\tapic_host={cls.apic}\tactual_host={cls.apic}"
            '\tcomponent="topSystem"'
        )
        events = [
            {
                "time": anchor,
                "host": "splunk-hf-01",
                "source": "cisco_nexus_aci://classInfo_topSystem",
                "sourcetype": "cisco:dc:aci:class",
                "index": "cisco_dc",
                "event": aci,
            },
            {
                "time": anchor,
                "host": "mr-mixed-01",
                "source": "cisco_meraki_devices::networking_inventory",
                "sourcetype": "meraki:devices",
                "index": "cisco_meraki",
                "event": {
                    "name": "MR-MIXED-01",
                    "networkId": cls.network,
                    "serial": f"Q2XX-MIXED-{token.upper()[:4]}",
                    "model": "MR46",
                    "productType": "wireless",
                    "organizationId": cls.organization,
                },
            },
            {
                "time": anchor,
                "host": "node-mixed",
                "source": "kubernetes",
                "sourcetype": "kube:object:nodes",
                "index": "k8s",
                "event": {
                    "type": "MODIFIED",
                    "object": {
                        "apiVersion": "v1",
                        "kind": "Node",
                        "metadata": {"name": "node-mixed", "uid": f"uid-{token}"},
                        "spec": {},
                        "status": {
                            "addresses": [
                                {"type": "InternalIP", "address": "10.10.90.11"}
                            ]
                        },
                    },
                },
                "fields": {
                    "metric_source": "kubernetes",
                    "k8s.cluster.name": cls.cluster,
                    "k8s.resource.name": "nodes",
                },
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed-case-scope.ndjson"
            path.write_text(
                "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in events)
            )
            if cls.lab.load([path]) != len(events):
                raise RuntimeError("did not load every mixed-case inventory event")
        deadline = time.monotonic() + 90
        spl = (
            "search (index=cisco_dc sourcetype=cisco:dc:aci:class) OR "
            "(index=cisco_meraki sourcetype=meraki:devices) OR "
            "(index=k8s sourcetype=kube:object:nodes) "
            f"{json.dumps(token)} OR {json.dumps(token.upper())} | stats count"
        )
        while True:
            counted = cls.lab.search(spl, *cls.window)
            if counted and int(counted[0].get("count", 0)) >= len(events):
                return
            if time.monotonic() > deadline:
                raise RuntimeError("mixed-case inventory events were not indexed")
            time.sleep(2)

    def _device(self, authority: str) -> dict:
        matches = [
            row
            for row in self.rows
            if row.get("row_type") == "device"
            and row.get("device_authority") == authority
        ]
        self.assertEqual(len(matches), 1, authority)
        return matches[0]

    def test_mixed_case_apic_host_is_mapped(self):
        row = self._device(self.apic)
        self.assertTrue(row["device_id"].startswith("aci:"))
        self.assertEqual(row.get("mapping_status"), "mapped")
        self.assertEqual(row.get("scope"), self.scope)
        self.assertEqual(row.get("cluster"), self.cluster)

    def test_mixed_case_meraki_organization_and_network_are_mapped(self):
        row = self._device(self.meraki_authority)
        self.assertTrue(row["device_id"].startswith("meraki:"))
        self.assertEqual(row.get("mapping_status"), "mapped")
        self.assertEqual(row.get("scope"), self.scope)

    def test_mixed_case_kubernetes_cluster_is_mapped(self):
        row = self._device(self.cluster)
        self.assertTrue(row["device_id"].startswith("host:"))
        self.assertEqual(row.get("mapping_status"), "mapped")
        self.assertEqual(row.get("cluster"), self.cluster)
