"""Static contract of the bounded map inventory read (adm_topology_with_vsphere).

adm_topology reads each inventory object once (newest first) before its
window-wide eventstats, and stays the public V1 selector named by the pipeline
interface. The vSphere part of the map read uses current VMM state, while
recent=0 callers keep the legacy window. Live behavior is exercised by
tests/splunk/test_vsphere_paths.py and tests/splunk/test_topology.py.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from tests.test_path_trace_macros import closure, definition, stanzas
from tools.cisco_migration.common import _macro_definition_equal

ROOT = Path(__file__).resolve().parents[1]
DEDUP_STEP = (
    '| eval adm_inventory_key=case(sourcetype=="cisco:dc:aci:class", '
    '"aci|".apic_host."|".component."|".dn, sourcetype=="cisco:dc:nexus9k", '
    '"nx|".device."|".component."|".md5(replace(_raw, '
    '"\\"timestamp\\":\\s*\\"[^\\"]*\\"", ""))) \n'
    "| dedup adm_inventory_key keepempty=true \n"
    "| fields - adm_inventory_key \n"
)


class TopologyInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = stanzas()
        cls.d = {k: definition(v) for k, v in cls.m.items() if "definition = " in v}

    def test_topology_reads_each_object_once_before_eventstats(self):
        topology = self.d["adm_topology"]
        self.assertEqual(topology.count(DEDUP_STEP), 1)
        head = topology.split(DEDUP_STEP)[0]
        self.assertNotIn("| append", head)
        self.assertNotIn("eventstats", head)

    def test_public_selector_and_surface_match_the_packaged_topology(self):
        interface = json.loads(
            (ROOT / "research/cisco-pipeline-interface.json").read_text()
        )
        packaged = self.d["adm_topology"].replace("\n", "")
        selector = next(
            s
            for s in interface["activation"]["cutover_selectors"]
            if s["name"] == "adm_topology"
        )
        self.assertTrue(_macro_definition_equal(packaged, selector["before"]))
        surface = next(
            s for s in interface["public_surfaces"] if s["surface"] == "topology"
        )
        self.assertTrue(_macro_definition_equal(packaged, surface["v1"]["definition"]))

    def test_map_inventory_reads_the_public_topology_and_recent_vmm_state(self):
        mapped = self.d["adm_topology_with_vsphere"]
        self.assertIn("`adm_topology`", mapped)
        self.assertIn("`adm_map_vsphere_inventory`", mapped)
        self.assertIn(
            '`adm_vsphere_vmm_rows("1", "1")`', self.d["adm_map_vsphere_inventory"]
        )

    def test_split_map_inventory_is_the_macro_append(self):
        # The map reads adm_topology and adm_map_vsphere_inventory side by
        # side and concatenates them in this order (frontend useGraphQuery).
        mapped = self.d["adm_topology_with_vsphere"]
        self.assertEqual(
            mapped.replace("\\\n", "\n").strip().split("\n"),
            ["`adm_topology` ", "| append [| `adm_map_vsphere_inventory`]"],
        )
        client = (ROOT / "frontend/src/data/useGraphQuery.ts").read_text()
        self.assertIn('"`adm_topology`",\n  "| `adm_map_vsphere_inventory`",', client)

    def test_map_vmm_half_is_the_filtered_reader_without_discarded_uplinks(self):
        reader = self.d["adm_vsphere_topology(2)"]
        self.assertEqual(
            reader.replace("\\\n", "\n").strip().split("\n"),
            [
                "`adm_vsphere_vmm_rows($version$, $recent$)` ",
                "| append [| `adm_vsphere_uplinks($version$)` | eval adm_uplink_row=1] ",
                "| `adm_vsphere_rows_finish`",
            ],
        )
        half = self.d["adm_map_vsphere_inventory"].strip()
        self.assertTrue(
            half.startswith(
                '`adm_vsphere_vmm_rows("1", "1")` | `adm_vsphere_rows_finish` | where '
            )
        )
        keep = half.split(" | where ", 1)[1]
        self.assertNotIn("uplink", keep)
        self.assertNotIn("network_device", keep)
        # Uplink reads emit only these kinds, which the map filter drops.
        uplinks = self.d["adm_vsphere_uplinks(1)"]
        self.assertEqual(
            set(re.findall(r'device_kind="([a-z_]+)"', uplinks)), {"network_device"}
        )
        self.assertEqual(set(re.findall(r'link_kind="([a-z_]+)"', uplinks)), {"uplink"})

    def test_legacy_vsphere_reader_keeps_the_window(self):
        self.assertEqual(
            self.d["adm_vsphere_topology(1)"].strip(),
            '`adm_vsphere_topology("$version$", "0")`',
        )
        body = self.d["adm_vsphere_vmm_rows(2)"]
        self.assertIn("`adm_topology_inventory_time_bounds($recent$)`", body)
        self.assertIn("`adm_topology_inventory_older_bounds($recent$)`", body)
        recent = self.d["adm_topology_inventory_time_bounds(1)"]
        legacy = self.d["adm_topology_inventory_time_bounds"]
        self.assertIn(
            "max(0,info_min_time-`adm_topology_inventory_lookback_seconds`)", legacy
        )
        self.assertIn(
            "max(0,info_min_time-`adm_topology_inventory_lookback_seconds`))",
            recent,
        )
        older = self.d["adm_topology_inventory_older_bounds(1)"]
        self.assertIn("latest=if($recent$==1,", older)
        self.assertIn(", earliest)", older)

    def test_bounded_inventory_stays_outside_the_captured_graph(self):
        captured = closure(self.m, "adm_graph(4)")
        for name in (
            "adm_topology",
            "adm_topology_with_vsphere",
            "adm_map_vsphere_inventory",
            "adm_vsphere_vmm_rows(2)",
            "adm_vsphere_rows_finish",
            "adm_vsphere_topology(2)",
            "adm_topology_inventory_time_bounds(1)",
            "adm_topology_inventory_older_bounds(1)",
            "adm_topology_inventory_recent_seconds",
        ):
            self.assertIn(name, self.m)
            self.assertNotIn(name, captured)


if __name__ == "__main__":
    unittest.main()
