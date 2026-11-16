"""adm_vsphere_topology, adm_path_trace and adm_device_flows against the local Splunk lab.

Skipped unless ADM_LAB=1. Prerequisites: `tests/splunk/lab.sh up` and `tests/splunk/lab.sh install`.
Resets the lab indexes and loads fixtures/raw-aci/*.ndjson plus the VDS IPFIX record of
fixtures/raw-vmware. Expectations come from the two scenario.json files.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ACI = json.loads((ROOT / "fixtures" / "raw-aci" / "scenario.json").read_text("utf-8"))
# 2026-10-07T11:00:00Z .. 12:30:00Z, around the ACI scenario window.
WINDOW = ("1791370800", "1791376200")


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class VspherePathsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        subprocess.run([str(HERE / "lab.sh"), "reset"], check=True, capture_output=True)
        lab.wait_ready()
        files = sorted((ROOT / "fixtures" / "raw-aci").glob("*.ndjson")) + [
            ROOT / "fixtures" / "raw-vmware" / "vds_ipfix.ndjson",
            ROOT / "fixtures" / "raw-vmware" / "aci_vmm_adjacency.ndjson",
            ROOT / "fixtures" / "raw-vmware" / "aci_fabric_evidence.ndjson",
        ]
        sent = lab.load(files)
        deadline = time.time() + 180
        while time.time() < deadline:
            got = int(
                lab.search("search index=* NOT index=_* | stats count", "0", "now")[0][
                    "count"
                ]
            )
            if got >= sent:
                break
            time.sleep(2)

    def search(self, spl: str) -> list[dict]:
        return self.lab.search(spl, *WINDOW)

    def test_vsphere_rows_from_aci_vmm(self):
        rows = self.search("| `adm_vsphere_topology(1)`")
        devices = {r["device_id"]: r for r in rows if r.get("row_type") == "device"}
        kinds = sorted(r["device_kind"] for r in devices.values())
        self.assertEqual(kinds, ["hypervisor", "hypervisor", "virtual_switch"])
        vds = next(r for r in devices.values() if r["device_kind"] == "virtual_switch")
        self.assertEqual(vds["name"], "vmm-shop")
        self.assertEqual(vds["switch_type"], "vds")
        ports = {
            r["b_device_name"]: r
            for r in rows
            if r.get("row_type") == "link" and r.get("link_kind") == "virtual_port"
        }
        vms = {v["name"]: v for v in ACI["vms"]}
        self.assertEqual(set(ports), set(vms))
        for name, vm in vms.items():
            port = ports[name]
            self.assertEqual(port["a_device"], vds["device_id"])
            self.assertEqual(port["mac"], vm["mac"].lower())
            self.assertEqual(port["ip"], vm["ip"])
            self.assertEqual(port["vlan"], vm["encap"].replace("vlan-", ""))
            hv = devices[port["hypervisor"]]
            self.assertEqual(hv["name"], vm["hypervisor"])
            leaf = next(s for s in ACI["fabric"]["switches"] if s["name"] == vm["leaf"])
            self.assertEqual(
                as_list(port.get("attach_nodes")), [f"pod-1/node-{leaf['node_id']}"]
            )
            self.assertEqual(port.get("attach_interface"), vm["interface"])

    def test_hvsadj_uplinks_pin_the_vmnic_by_lldp_chassis_mac(self):
        rows = self.search("| `adm_vsphere_topology(1)`")
        hv_name = {
            r["device_id"]: r["name"]
            for r in rows
            if r.get("row_type") == "device" and r.get("device_kind") == "hypervisor"
        }
        uplinks = sorted(
            (
                hv_name[r["hypervisor"]],
                r.get("a_interface"),
                r["b_device"],
                r["b_interface"],
            )
            for r in rows
            if r.get("link_kind") == "uplink"
        )
        switches = {s["name"]: s for s in ACI["fabric"]["switches"]}
        want = sorted(
            (
                h["name"],
                "vmnic2",
                f"pod-1/node-{switches[h['leaf']]['node_id']}",
                h["interface"].replace("eth", "Ethernet"),
            )
            for h in ACI["hypervisors"]
        )
        self.assertEqual(uplinks, want)
        self.assertFalse(
            [r for r in rows if r.get("device_kind") == "network_device"],
            "a host whose neighbor is the leaf itself has no intermediate device",
        )

    def test_vsphere_v2_rows_are_hashed_and_scoped(self):
        rows = self.search("| `adm_vsphere_topology(2)`")
        ids = [r["device_id"] for r in rows if r.get("row_type") == "device"]
        self.assertTrue(ids)
        self.assertTrue(all(len(i) == len("vsphere:") + 64 for i in ids))

    def test_path_trace_is_bounded_to_the_pair(self):
        rows = self.search("| `adm_path_trace(10.30.40.25,10.20.30.40)`")
        obs = {r["observer"]: r for r in rows if r.get("row_type") == "observation"}
        self.assertIn("netflow:192.0.2.73:ifIndex 18>ifIndex 14", obs)
        self.assertIn("aci_acllog:pod-1/node-103", obs)
        self.assertEqual(obs["aci_acllog:pod-1/node-103"]["drops"], "1")
        vs = [r for r in rows if r.get("link_kind") == "virtual_port"]
        self.assertEqual(len([r for r in rows if r.get("link_kind") == "uplink"]), 2)
        self.assertEqual(sorted(r["ip"] for r in vs), ["10.20.30.40", "10.30.40.25"])
        endpoints = [r for r in rows if r.get("row_type") == "endpoint"]
        self.assertTrue(
            all(r["ip"] in ("10.30.40.25", "10.20.30.40") for r in endpoints)
        )

    def test_path_trace_records_are_totals_with_bounded_rows(self):
        rows = self.search("| `adm_path_trace(10.30.40.25,10.20.30.40)`")
        obs = [r for r in rows if r.get("row_type") == "observation"]
        self.assertTrue(obs)
        self.assertLessEqual(len(obs), 200)
        raw = self.search(
            "| `adm_path_trace(10.30.40.25,10.20.30.40)` "
            '| where row_type="observation" | stats sum(records) AS total'
        )
        self.assertEqual(int(raw[0]["total"]), sum(int(r["records"]) for r in obs))
        self.assertTrue(all("dest_port_count" in r for r in obs))

    def test_map_topology_adds_only_virtual_ports_switches_and_hosts(self):
        rows = self.search("search `adm_topology_with_vsphere`")
        base = self.search("search `adm_topology`")
        extra = len(rows) - len(base)
        self.assertGreater(extra, 0)
        vs = [r for r in rows if r.get("link_kind") == "virtual_port"]
        self.assertTrue(vs and all(r.get("mac") and r.get("ip") for r in vs))
        self.assertFalse([r for r in rows if r.get("link_kind") == "uplink"])

    def test_map_vmm_half_equals_the_filtered_reader(self):
        # The map reads `adm_topology` and this half side by side; skipping the
        # uplink append must not change the rows the map's filter keeps.
        keep = (
            '| where (row_type=="link" AND link_kind=="virtual_port") OR '
            '(row_type=="device" AND (device_kind=="virtual_switch" '
            'OR device_kind=="hypervisor"))'
        )
        half = self.search("| `adm_map_vsphere_inventory`")
        filtered = self.search(f'| `adm_vsphere_topology("1", "1")` {keep}')
        self.assertTrue(half)

        def canon(rows):
            # generated_at is the meta row's now(); each search has its own.
            return sorted(
                json.dumps(
                    {k: v for k, v in r.items() if k != "generated_at"}, sort_keys=True
                )
                for r in rows
            )

        self.assertEqual(canon(half), canon(filtered))
        combined = self.search("search `adm_topology_with_vsphere`")
        base = self.search("search `adm_topology`")
        self.assertEqual(canon(combined), canon(base + half))

    def test_path_trace_spine_evidence(self):
        rows = self.search("| `adm_path_trace(10.30.40.25,10.20.30.40)`")
        ev = [r for r in rows if r.get("row_type") == "fabric_evidence"]
        isis = sorted(
            (r["node"], r["interface"], r.get("peer_node"))
            for r in ev
            if r["evidence_kind"] == "isis_adjacency"
        )
        # Up adjacencies only; leaf-103 -> spine-202 is down in the scenario.
        self.assertIn(("pod-1/node-103", "eth1/49.9", "pod-1/node-201"), isis)
        self.assertNotIn(("pod-1/node-103", "eth1/50.9", "pod-1/node-202"), isis)
        self.assertEqual(len(isis), 5)
        coop = sorted(
            (r["node"], r["mac"], r["citizen"])
            for r in ev
            if r["evidence_kind"] == "coop_endpoint"
        )
        self.assertEqual(
            coop,
            sorted(
                (f"pod-1/node-{n}", mac, tep)
                for n in ("201", "202")
                for mac, tep in (
                    ("00:50:56:AA:10:40", "10.0.200.102"),
                    ("00:50:56:AA:40:25", "10.0.200.103"),
                )
            ),
        )

    def test_device_flows_for_vds_exporter_and_leaf(self):
        vds = self.search("| `adm_device_flows(192.0.2.73)`")
        self.assertEqual(len(vds), 1)
        self.assertEqual(
            (vds[0]["src"], vds[0]["dst"], vds[0]["dest_port"], vds[0]["protocol"]),
            ("10.30.40.25", "10.20.30.40", "5432", "tcp"),
        )
        self.assertEqual(vds[0]["total_conversations"], "1")
        leaf = self.search("| `adm_device_flows(pod-1/node-103)`")
        blocked = [r for r in leaf if r.get("blocked") == "1"]
        self.assertEqual(
            [(r["src"], r["dst"], r["dest_port"]) for r in blocked],
            [("10.30.40.25", "10.20.30.40", "5432")],
        )
        self.assertTrue(all(r["device"] == "pod-1/node-103" for r in leaf))
        # The cap counts device records after the device filter; well under
        # it, nothing is marked capped and totals are exact.
        for rows in (vds, leaf):
            self.assertEqual({r["records_capped"] for r in rows}, {"0"})

    def test_device_flows_cap_marks_truncation_after_the_device_filter(self):
        # With the cap at one record, a device with more records keeps exactly
        # one device record (not an unrelated free-text match) and says so.
        total = self.search(
            "| `adm_device_flows(pod-1/node-103)` | stats sum(flows) AS flows"
        )
        self.assertGreater(int(total[0]["flows"]), 1)
        path = "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_path_trace_limit"
        self.lab._mgmt("POST", path, {"definition": "1"}).close()
        try:
            rows = self.search(
                "| `adm_device_flows(pod-1/node-103)` "
                "| stats sum(flows) AS flows max(records_capped) AS capped"
            )
        finally:
            self.lab._mgmt("POST", path, {"definition": "5000"}).close()
        self.assertEqual((rows[0]["flows"], rows[0]["capped"]), ("1", "1"))

    def test_resolve_value_is_validated_before_search(self):
        for value in ('x" OR ip="*', "a*", "a b"):
            with self.assertRaises(Exception, msg=value):
                self.search(f"| `adm_path_trace_resolve({value})`")
        for value in ("10.30.40.25", "orders-db-01", "vm[1]"):
            self.search(f"| `adm_path_trace_resolve({value})`")

    def test_l3out_rows_carry_their_truncation_marker(self):
        rows = [
            r
            for r in self.search("| `adm_path_trace(10.30.40.25,10.20.30.40)`")
            if r.get("row_type") in ("l3out_path", "l3out_subnet")
        ]
        self.assertTrue(all(r.get("truncated") == "0" for r in rows), rows[:2])


if __name__ == "__main__":
    unittest.main()
