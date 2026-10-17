"""Contract checks for TA-grounded combined campus/Meraki raw fixtures."""

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "raw-networking"
BASE_TIME = "2026-10-16T13:00:00Z"


def read_events(name: str, directory: Path = FIXTURES) -> list[dict]:
    with (directory / name).open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def body(event: dict) -> dict:
    value = event["event"]
    return json.loads(value) if isinstance(value, str) else value


class CiscoCombinedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="adm-networking-fixtures-")
        cls.generated_dir = Path(cls._tmp.name)
        command = [
            sys.executable,
            "tools/gen_raw_fixtures.py",
            "--scenario",
            "networking",
            "--base-time",
            BASE_TIME,
            "--output-dir",
            str(cls.generated_dir),
        ]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def events(self, name: str) -> list[dict]:
        return read_events(name, self.generated_dir)

    def test_catalyst_snapshot_contract(self) -> None:
        [event] = self.events("catalyst_clients.ndjson")
        raw = body(event)
        self.assertEqual(event["sourcetype"], "cisco:dnac:client")
        self.assertEqual(event["index"], "cisco_catalyst")
        self.assertEqual(event["source"], "cisco_catalyst_dnac_client://campus_wired")
        self.assertEqual(raw["macAddress"], "02:61:00:00:00:20")
        self.assertEqual(raw["id"], raw["macAddress"])
        self.assertEqual(raw["ipv4Address"], "10.61.0.20")
        self.assertEqual(raw["type"], "Wired")
        self.assertEqual(raw["connectionStatus"], "connected")
        self.assertEqual(
            raw["connectedNetworkDevice"]["connectedNetworkDeviceName"], "CAMPUS-SW-01"
        )
        self.assertEqual(
            raw["connectedNetworkDevice"]["connectedNetworkDeviceType"], "Switch"
        )
        self.assertEqual(
            raw["connectedNetworkDevice"]["interfaceName"], "GigabitEthernet1/0/24"
        )
        self.assertTrue(raw["cisco_catalyst_host"].startswith("https://"))
        self.assertNotIn("collected_time", raw)
        self.assertNotIn("scope_profile", raw)
        self.assertNotIn("vrf", raw)

    def test_meraki_association_roam_replay_and_negative_evidence(self) -> None:
        events = self.events("meraki_associations.ndjson")
        records = [body(item) for item in events]
        self.assertTrue(
            all(item["sourcetype"] == "meraki:accesspoints" for item in events)
        )
        self.assertTrue(all(item["index"] == "cisco_meraki" for item in events))
        self.assertTrue(all(record["type"] == "association" for record in records))
        self.assertFalse(any("disassociation" in record["type"] for record in records))

        roam = [
            record for record in records if record["clientMac"] == "02:71:00:00:00:20"
        ]
        observed_roam = {record["occurredAt"]: record for record in roam}
        roam = [observed_roam[key] for key in sorted(observed_roam)]
        self.assertEqual(
            [record["deviceSerial"] for record in roam],
            [
                "Q2XX-DEMO-0001",
                "Q2XX-DEMO-0002",
            ],
        )
        for record in roam:
            self.assertIn("organizationId", record)
            self.assertIn("networkId", record)
            self.assertEqual(record["eventData"]["client_mac"], record["clientMac"])
            self.assertEqual(record["eventData"]["client_ip"], "10.71.0.20")
            self.assertEqual(record["ssidNumber"], 1)
        # The API example supports an exact replay case; no synthetic event ID is added.
        replay_count = sum(record == roam[0] for record in records)
        self.assertEqual(replay_count, 2)
        self.assertNotIn("scope_profile", records[0])

        conflict = [
            record for record in records if record["clientMac"] == "02:71:00:00:00:22"
        ]
        self.assertEqual(
            {item["eventData"]["client_ip"] for item in conflict},
            {
                "10.71.0.22",
                "10.71.0.23",
            },
        )
        stale = next(
            record for record in records if record["clientMac"] == "02:71:00:00:00:88"
        )
        self.assertLess(stale["occurredAt"], BASE_TIME)

    def test_meraki_inventory_and_cataloged_topology_shape(self) -> None:
        devices = self.events("meraki_inventory.ndjson")
        inventory = [body(item) for item in devices]
        self.assertEqual(len(inventory), 3)
        self.assertEqual(
            {item["productType"] for item in inventory}, {"wireless", "switch"}
        )
        self.assertTrue(all(item["organizationId"] == "org-demo" for item in inventory))

        [topology_event] = self.events("meraki_topology.ndjson")
        topology = body(topology_event)
        self.assertEqual(topology_event["sourcetype"], "meraki:custom")
        self.assertEqual(
            topology["operation_id"],
            "getOrganizationSwitchPortsTopologyDiscoveryByDevice",
        )
        self.assertEqual(topology["ports"][0]["portId"], "10")
        self.assertEqual(topology["ports"][0]["lldp"][0]["value"], "MR-NXOS-01")
        self.assertEqual(topology["ports"][1]["portId"], "11")
        self.assertEqual(topology["ports"][1]["lldp"][0]["value"], "MR-NXOS-02")

    def test_sdwan_and_ms390_keep_distinct_raw_field_contracts(self) -> None:
        campus = [body(item) for item in self.events("campus_netflow.ndjson")]
        sdwan = [body(item) for item in self.events("sdwan_netflow.ndjson")]
        meraki = [body(item) for item in self.events("meraki_ms390_ipfix.ndjson")]
        self.assertEqual(len(campus), 1)
        self.assertEqual(len(sdwan), 1)
        for field in (
            "src_ip",
            "dest_ip",
            "src_port",
            "dest_port",
            "timestamp",
            "endtime",
        ):
            self.assertEqual(campus[0][field], sdwan[0][field])
        self.assertNotIn("vpn_id", campus[0])
        self.assertNotIn("tloc_local_system_ip", campus[0])
        self.assertEqual(campus[0]["exporter_ip"], "10.61.255.2")
        self.assertEqual(campus[0]["observation_domain_id"], 601)
        self.assertGreaterEqual(len(meraki), 3)
        self.assertIn("vpn_id", sdwan[0])
        self.assertEqual(sdwan[0]["ingress_overlay_session_id"], 90101)
        self.assertEqual(sdwan[0]["egress_overlay_session_id"], 90201)
        self.assertFalse(any(key.startswith("tloc_") for key in sdwan[0]))
        self.assertNotIn("flow_start_time", sdwan[0])
        self.assertNotIn("flow_end_time", sdwan[0])
        for field in ("flow_start_time_milli", "flow_end_time_milli"):
            self.assertIsInstance(sdwan[0][field], int)
        self.assertEqual(
            sdwan[0]["flow_end_time_milli"] - sdwan[0]["flow_start_time_milli"],
            220,
        )
        self.assertTrue(all("vpn_id" not in item for item in meraki))
        self.assertTrue(all("tloc_local_system_ip" not in item for item in meraki))
        self.assertTrue(all("vendor_product" not in item for item in meraki))
        positive_meraki = [item for item in meraki if item["src_ip"] == "10.71.0.20"]
        self.assertTrue(
            all(item["exporter_ip"] == "10.71.0.2" for item in positive_meraki)
        )
        self.assertTrue(
            all(item["observation_domain_id"] == 390 for item in positive_meraki)
        )
        missing_exporter = next(
            item for item in meraki if item["src_ip"] == "10.71.0.99"
        )
        self.assertNotIn("exporter_ip", missing_exporter)
        self.assertIn("src_mac", meraki[0])
        self.assertTrue(
            all(
                item["sourcetype"] == "stream:netflow"
                for item in self.events("meraki_ms390_ipfix.ndjson")
            )
        )
        self.assertTrue(
            all(
                item["sourcetype"] == "stream:netflow"
                for item in self.events("sdwan_netflow.ndjson")
            )
        )
        provenance = (FIXTURES / "FIELDS.md").read_text()
        self.assertIn("`vendor_product` alias is broad for", provenance)

        profiles = json.loads((self.generated_dir / "source-profiles.json").read_text())
        mappings = profiles["network_source_scope"]
        self.assertTrue(all(len(mapping) >= 11 for mapping in mappings))
        stream_profiles = {
            mapping["profile"]: mapping
            for mapping in mappings
            if mapping["source"] == "stream_ipfix"
        }
        self.assertEqual(
            set(stream_profiles),
            {
                "catalyst_campus_fnf",
                "catalyst_sdwan_ipfix",
                "meraki_ms390_ipfix",
                "standard_netflow",
            },
        )
        standard = [
            mapping
            for mapping in mappings
            if mapping["source"] == "stream_ipfix"
            and mapping["profile"] == "standard_netflow"
        ]
        self.assertEqual(
            {mapping["source_authority"] for mapping in standard},
            {"192.0.2.101", "192.0.2.102", "192.0.2.103"},
        )
        for mapping in standard:
            self.assertEqual(mapping["domain_kind"], "exporter")
            self.assertEqual(mapping["observation_domain_present"], "0")
            self.assertEqual(mapping["observation_domain_id"], "")
            self.assertEqual(mapping["vpn_id"], "")
            self.assertEqual(mapping["routing_domain"], "")
            self.assertEqual(mapping["scope"], "campus-aci")
            self.assertEqual(mapping["cluster"], "cilium-aci-east")

        aci_netflow = [body(item) for item in self.events("aci_netflow.ndjson")]
        self.assertEqual(
            {item["exporter_ip"] for item in aci_netflow},
            {"192.0.2.101", "192.0.2.102", "192.0.2.103"},
        )

    def test_aci_and_nxos_vendor_raw_evidence_is_present(self) -> None:
        aci_components = [
            item
            for item in self.events("aci_stats.ndjson")
            if 'component="fvCEp"' in str(item["event"])
        ]
        self.assertTrue(aci_components)
        aci_nd = [body(item) for item in self.events("aci_nd_flows.ndjson")]
        self.assertTrue(any("10.61.0.20" in json.dumps(item) for item in aci_nd))

        inventory = self.events("nxos_inventory.ndjson")
        self.assertTrue(inventory)
        self.assertTrue(
            all(item["sourcetype"] == "cisco:dc:nexus9k" for item in inventory)
        )
        nxos_flows = [body(item) for item in self.events("nxos_nd_flows.ndjson")]
        self.assertTrue(any("10.71.0.20" in json.dumps(item) for item in nxos_flows))
        endpoints = [body(item) for item in self.events("nxos_nd_endpoints.ndjson")]
        self.assertTrue(any("10.10.20.12" in json.dumps(item) for item in endpoints))

    def test_two_cluster_cilium_kubernetes_hubble_and_otel_evidence(self) -> None:
        kube = self.events("kube_objects.ndjson")
        clusters = {item["fields"]["k8s.cluster.name"] for item in kube}
        self.assertEqual(clusters, {"cilium-aci-east", "cilium-nxos-west"})
        for resource in ("pods", "nodes", "services", "endpointslices"):
            self.assertTrue(
                any(item["fields"]["k8s.resource.name"] == resource for item in kube)
            )

        hubble = [
            json.loads(item["event"]) for item in self.events("hubble_flows.ndjson")
        ]
        inbound = [
            item["flow"]
            for item in hubble
            if item["flow"].get("trace_observation_point") == "TO_ENDPOINT"
            and item["flow"]["IP"]["source"] in {"10.61.0.20", "10.71.0.20"}
        ]
        self.assertEqual(len(inbound), 2)
        self.assertEqual(
            {flow["IP"]["source"] for flow in inbound},
            {"10.61.0.20", "10.71.0.20"},
        )

        traces = self.events("otel_traces.ndjson")
        self.assertTrue(
            any(
                item["fields"]["k8s.cluster.name"] == "cilium-aci-east"
                for item in traces
            )
        )
        self.assertTrue(
            any(
                item["fields"]["k8s.cluster.name"] == "cilium-nxos-west"
                for item in traces
            )
        )
        spans = [body(item) for item in traces]
        self.assertTrue(
            any(
                span["attributes"].get("client.address") == "10.61.0.20"
                for span in spans
            )
        )
        self.assertTrue(
            any(
                span["attributes"].get("client.address") == "10.71.0.20"
                for span in spans
            )
        )
        span_ids: dict[str, set[str]] = {}
        for span in spans:
            span_ids.setdefault(span["trace_id"], set()).add(span["span_id"])
        for span in spans:
            if span["parent_span_id"]:
                self.assertIn(span["parent_span_id"], span_ids[span["trace_id"]])

        process_connect = [
            body(item)["process_connect"] for item in self.events("isovalent.ndjson")
        ]
        isovalent_sources = {
            item["source"]: body(item) for item in self.events("isovalent.ndjson")
        }
        self.assertEqual(
            set(isovalent_sources),
            {"http:isovalent-aci", "http:isovalent-nxos"},
        )
        source_profiles = json.loads(
            (self.generated_dir / "source-profiles.json").read_text()
        )
        hec_profiles = {
            entry["observer"]: entry
            for entry in source_profiles["legacy_observer_scope"]
            if entry["observer_kind"] == "hec_source"
        }
        self.assertEqual(
            hec_profiles["http:isovalent-aci"]["cluster"], "cilium-aci-east"
        )
        self.assertEqual(
            hec_profiles["http:isovalent-nxos"]["cluster"], "cilium-nxos-west"
        )
        self.assertTrue(
            all(
                event.get("fields") is None for event in self.events("isovalent.ndjson")
            )
        )
        client_ips = {"10.61.0.20", "10.71.0.20"}
        self.assertFalse(
            any(item["source_ip"] in client_ips for item in process_connect)
        )
        # Same display names remain distinct through the cluster fields.
        self.assertEqual(len(clusters), 2)

    def test_fixed_anchor_is_reproducible_and_later_than_snapshot(self) -> None:
        before = (self.generated_dir / "sdwan_netflow.ndjson").read_bytes()
        second_dir = tempfile.TemporaryDirectory(
            prefix="adm-networking-fixtures-repeat-"
        )
        subprocess.run(
            [
                sys.executable,
                "tools/gen_raw_fixtures.py",
                "--scenario",
                "networking",
                "--base-time",
                BASE_TIME,
                "--output-dir",
                second_dir.name,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        after = (Path(second_dir.name) / "sdwan_netflow.ndjson").read_bytes()
        self.assertEqual(before, after)
        catalyst = body(self.events("catalyst_clients.ndjson")[0])
        flow = body(self.events("sdwan_netflow.ndjson")[0])
        snapshot_time = datetime.fromtimestamp(
            catalyst["lastUpdatedTime"] / 1000, tz=timezone.utc
        )
        flow_time = datetime.fromisoformat(flow["timestamp"].replace("Z", "+00:00"))
        self.assertLess(snapshot_time, flow_time)
        manifest = json.loads(
            (self.generated_dir / "capture-manifest.json").read_text()
        )
        self.assertEqual(manifest["scenario_id"], "campus-meraki-two-cluster")
        self.assertEqual(manifest["output_events"]["catalyst_clients.ndjson"], 1)
        self.assertEqual(manifest["index_events"]["netflow"], 39)
        hec_times = [
            item["time"]
            for path in self.generated_dir.glob("*.ndjson")
            for item in read_events(path.name, self.generated_dir)
        ]
        self.assertEqual(
            manifest["ingestion_window"]["start"],
            datetime.fromtimestamp(min(hec_times), tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        )
        self.assertEqual(
            manifest["ingestion_window"]["end"],
            datetime.fromtimestamp(max(hec_times), tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        )
        self.assertIn("sha256", manifest["source_profiles"])
        second_dir.cleanup()

    def test_rebasing_shifts_hec_times_and_body_event_times(self) -> None:
        second_dir = tempfile.TemporaryDirectory(
            prefix="adm-networking-fixtures-rebase-"
        )
        self.addCleanup(second_dir.cleanup)
        second_base = "2026-10-18T13:00:00Z"
        subprocess.run(
            [
                sys.executable,
                "tools/gen_raw_fixtures.py",
                "--scenario",
                "networking",
                "--base-time",
                second_base,
                "--output-dir",
                second_dir.name,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        shift = 2 * 24 * 60 * 60
        first_manifest = json.loads(
            (self.generated_dir / "capture-manifest.json").read_text()
        )
        second_manifest = json.loads(
            (Path(second_dir.name) / "capture-manifest.json").read_text()
        )
        self.assertEqual(
            first_manifest["output_events"], second_manifest["output_events"]
        )
        for filename in first_manifest["output_events"]:
            first = read_events(filename, self.generated_dir)
            second = read_events(filename, Path(second_dir.name))
            self.assertEqual(len(first), len(second), filename)
            for before, after in zip(first, second, strict=True):
                self.assertEqual(after["time"] - before["time"], shift, filename)

        first_aci_endpoint = body(self.events("aci_nd_endpoints.ndjson")[0])
        second_aci_endpoint = body(
            read_events("aci_nd_endpoints.ndjson", Path(second_dir.name))[0]
        )
        self.assertEqual(second_aci_endpoint["createTime"], "2026-10-18T13:00:00.000Z")
        self.assertEqual(
            datetime.fromisoformat(
                second_aci_endpoint["createTime"].replace("Z", "+00:00")
            )
            - datetime.fromisoformat(
                first_aci_endpoint["createTime"].replace("Z", "+00:00")
            ),
            timedelta(seconds=shift),
        )

        first_services = [
            body(item)
            for item in self.events("kube_objects.ndjson")
            if body(item).get("object", {}).get("kind") == "Service"
        ]
        second_services = [
            body(item)
            for item in read_events("kube_objects.ndjson", Path(second_dir.name))
            if body(item).get("object", {}).get("kind") == "Service"
        ]
        self.assertTrue(first_services and second_services)
        first_service_created = datetime.fromisoformat(
            first_services[0]["object"]["metadata"]["creationTimestamp"].replace(
                "Z", "+00:00"
            )
        )
        second_service_created = datetime.fromisoformat(
            second_services[0]["object"]["metadata"]["creationTimestamp"].replace(
                "Z", "+00:00"
            )
        )
        self.assertEqual(
            second_service_created - first_service_created, timedelta(seconds=shift)
        )
        second_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
