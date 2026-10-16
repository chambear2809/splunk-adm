"""Live SPL checks for time-qualified endpoint network metadata.

The suite is intentionally gated: it expects the integration branch's
``adm_network_resolve`` helper and a running lab, but never starts or resets
the lab itself.
"""

from __future__ import annotations

import json
import os
import unittest


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class NetworkHistoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import lab

        cls.lab = lab

    @staticmethod
    def _descriptor(source: str, samples: list[dict], mac: str = "AA") -> dict:
        return {
            "vf": 0,
            "ve": 100000,
            "fs": 0,
            "ls": 10000,
            "p": 3,
            "kind": "endpoint",
            "id": source,
            "name": "test",
            "source": source,
            "ek": "ep:test/10.0.0.1/" + mac,
            "mac": mac,
            "nh": samples,
        }

    def resolve(self, descriptors: list[dict], start: int, end: int) -> dict:
        desc_expr = ",".join(
            "json_set(json_object(\"vf\",0,\"ve\",100000,\"fs\",0,\"ls\",10000,\"p\",3,\"kind\",\"endpoint\",\"id\",\"%s\",\"name\",\"test\",\"source\",\"%s\",\"ek\",\"ep:test/10.0.0.1/%s\",\"mac\",\"%s\"),\"nh\",json(%s))"
            % (
                d["id"],
                d["source"],
                d["mac"],
                d["mac"],
                json.dumps(json.dumps(d["nh"], separators=(",", ":"))),
            )
            for d in descriptors
        )
        query = (
            '| makeresults | eval adm_c_desc=mvappend(%s), adm_bfs=%d, adm_bls=%d, '
            'client_ip="10.0.0.1", scope="test" | `adm_resolve(c,client_ip)` '
            '| table adm_c_state adm_c_node'
        ) % (desc_expr, start, end)
        rows = self.lab.search(query)
        self.assertEqual(len(rows), 1, rows)
        node = json.loads(rows[0]["adm_c_node"])
        node["state"] = rows[0].get("adm_c_state")
        return node

    def test_stable_and_ab_a_use_consistent_scalar(self):
        stable = self.resolve(
            [self._descriptor("aci", [{"t": 1000, "v": "1030", "b": "bd"}])],
            1001,
            1002,
        )
        self.assertEqual(stable["attr_vlan"], "1030")
        self.assertEqual(stable["attr_bridge_domain"], "bd")
        aba = self.resolve(
            [
                self._descriptor(
                    "aci",
                    [
                        {"t": 1000, "v": "1030", "b": "bd"},
                        {"t": 1100, "v": "1031", "b": "bd2"},
                        {"t": 1200, "v": "1030", "b": "bd"},
                    ],
                )
            ],
            1001,
            1201,
        )
        self.assertIsNone(aba.get("attr_vlan"))
        self.assertEqual(aba.get("attr_vlan_status"), "varies")

    def test_before_change_and_missing_sample_do_not_extrapolate(self):
        before = self.resolve(
            [self._descriptor("aci", [{"t": 1200, "v": "1030", "b": "bd"}])],
            1001,
            1002,
        )
        self.assertIsNone(before.get("attr_vlan"))
        self.assertEqual(before.get("attr_vlan_status"), "incomplete")
        missing = self.resolve(
            [self._descriptor("aci", [{"t": 1000, "b": "bd"}])], 1001, 1002
        )
        self.assertIsNone(missing.get("attr_vlan"))
        self.assertEqual(missing.get("attr_vlan_status"), "incomplete")

    def test_freshness_gap_and_fieldwise_same_mac_fallback(self):
        gap = self.resolve(
            [
                self._descriptor(
                    "aci",
                    [
                        {"t": 1000, "v": "1030", "b": "bd"},
                        {"t": 2000, "v": "1030", "b": "bd"},
                    ],
                )
            ],
            1001,
            2001,
        )
        self.assertEqual(gap.get("attr_vlan_status"), "incomplete")
        fallback = self.resolve(
            [
                self._descriptor("aci", [{"t": 1000, "v": "1030"}]),
                self._descriptor("nd_endpoints", [{"t": 1000, "b": "nd-bd"}]),
            ],
            1001,
            1002,
        )
        self.assertEqual(fallback.get("attr_vlan"), "1030")
        self.assertEqual(fallback.get("attr_bridge_domain"), "nd-bd")

    def test_reject_wildcard_and_old_descriptor(self):
        wildcard = self.resolve(
            [
                self._descriptor("aci", [{"t": 1000, "v": "1030"}], mac="*"),
                self._descriptor("nd_endpoints", [{"t": 1000, "b": "nd-bd"}], mac="BB"),
            ],
            1001,
            1002,
        )
        self.assertIsNone(wildcard.get("attr_vlan"))
        self.assertIsNone(wildcard.get("attr_bridge_domain"))
        old = self._descriptor("aci", [])
        old.pop("nh")
        result = self.resolve([old], 1001, 1002)
        self.assertIsNone(result.get("attr_vlan"))
        self.assertIsNone(result.get("attr_bridge_domain"))

