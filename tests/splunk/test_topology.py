"""adm_topology test against the local Splunk lab.

Skipped unless ADM_LAB=1. Prerequisites: `tests/splunk/lab.sh up` and `tests/splunk/lab.sh install`.
Resets the lab indexes and loads fixtures/raw/*.ndjson itself. Expectations in
expected/topology.json are derived from fixtures/raw/scenario.json, not from search output.
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
RAW = HERE.parents[1] / "fixtures" / "raw"
EXPECTED = json.loads((HERE / "expected" / "topology.json").read_text("utf-8"))
WINDOW = (str(EXPECTED["window"]["earliest"]), str(EXPECTED["window"]["latest"]))


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class TopologyTest(unittest.TestCase):
    rows: list[dict]

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        subprocess.run([str(HERE / "lab.sh"), "reset"], check=True, capture_output=True)
        lab.wait_ready()
        sent = lab.load(sorted(RAW.glob("*.ndjson")))
        deadline = time.time() + 120
        while time.time() < deadline:
            got = int(
                lab.search("search index=* NOT index=_* | stats count", "0", "now")[0][
                    "count"
                ]
            )
            if got >= sent:
                break
            time.sleep(2)
        cls.rows = lab.search("`adm_topology`", *WINDOW)

    def of(self, kind: str) -> list[dict]:
        return [r for r in self.rows if r.get("row_type") == kind]

    def test_devices(self):
        devices = {r["device_id"]: r for r in self.of("device")}
        self.assertEqual(set(devices), set(EXPECTED["devices"]))
        for name, want in EXPECTED["devices"].items():
            got = devices[name]
            for key, value in want.items():
                if key == "sources":
                    self.assertEqual(sorted(as_list(got.get(key))), value, name)
                else:
                    self.assertEqual(got.get(key), value, f"{name}.{key}")

    def test_links_merge_both_cdp_directions(self):
        links = [
            (r["a_device"], r["a_interface"], r["b_device"], r["b_interface"])
            for r in self.of("link")
        ]
        self.assertEqual(sorted(links), sorted(tuple(x) for x in EXPECTED["links"]))
        self.assertTrue(all(r.get("link_source") == "cdp" for r in self.of("link")))
        self.assertTrue(all(r.get("last_seen") for r in self.of("link")))

    def test_interfaces(self):
        got = {f"{r['device_id']}|{r['interface']}": r for r in self.of("interface")}
        self.assertEqual(set(got), set(EXPECTED["interfaces"]))
        for key, want in EXPECTED["interfaces"].items():
            for field, value in want.items():
                self.assertEqual(got[key].get(field), value, f"{key}.{field}")
        for key in EXPECTED["interfaces_without_ifindex"]:
            self.assertIsNone(got[key].get("ifindex"), key)

    def test_meta(self):
        meta = self.of("meta")
        self.assertEqual(len(meta), 1)
        want = EXPECTED["meta"]
        for key in ("devices", "links", "interfaces"):
            self.assertEqual(meta[0].get(key), want[key], key)
        self.assertTrue(
            any(want["warning_contains"] in w for w in as_list(meta[0].get("warnings")))
        )
        self.assertTrue(meta[0].get("generated_at"))

    def test_empty_range_warns(self):
        rows = self.lab.search("`adm_topology`", "1", "2")
        self.assertEqual([r["row_type"] for r in rows], ["meta"])
        self.assertEqual(rows[0].get("devices"), "0")
        self.assertTrue(
            any("No network inventory" in w for w in as_list(rows[0].get("warnings")))
        )


if __name__ == "__main__":
    unittest.main()
