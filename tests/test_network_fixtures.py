"""Offline checks for ACI EPG-to-BD and observed VLAN fixture grounding."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "fixtures" / "raw-aci"


def events(name: str) -> list[dict]:
    return [json.loads(line) for line in (RAW / name).read_text().splitlines()]


def fields(event: str) -> dict[str, str]:
    result = {}
    for token in event.split("\t")[1:]:
        key, value = token.split("=", 1)
        result[key] = value.strip('"')
    return result


class NetworkFixtureTests(unittest.TestCase):
    def test_fvrsbd_relations_link_epgs_to_configured_bridge_domains(self) -> None:
        rows = events("aci_class.ndjson")
        relations = [
            (row["time"], fields(row["event"]))
            for row in rows
            if 'component="fvRsBd"' in row["event"]
        ]
        self.assertEqual(len(relations), 21)
        self.assertEqual(len({time for time, _ in relations}), 7)
        client = next(
            attrs
            for _, attrs in relations
            if attrs["dn"] == "uni/tn-shop/ap-clients/epg-win-clients/rsbd"
        )
        self.assertEqual(
            client,
            {
                "dn": "uni/tn-shop/ap-clients/epg-win-clients/rsbd",
                "forceResolve": "yes",
                "rType": "mo",
                "state": "formed",
                "status": "",
                "tCl": "fvBD",
                "tDn": "uni/tn-shop/BD-bd-clients",
                "tType": "mo",
                "tnFvBDName": "bd-clients",
                "apic_host": "192.0.2.50",
                "actual_host": "192.0.2.50",
                "component": "fvRsBd",
            },
        )

    def test_relations_use_network_classinfo_source_and_match_endpoint_poll(
        self,
    ) -> None:
        rows = events("aci_class.ndjson")
        relations = [row for row in rows if 'component="fvRsBd"' in row["event"]]
        self.assertEqual(
            {row["source"] for row in relations},
            {"cisco_nexus_aci://classInfo_adm_network"},
        )
        endpoint_polls = {
            row["time"] for row in rows if 'component="fvCEp"' in row["event"]
        }
        self.assertTrue(all(row["time"] in endpoint_polls for row in relations))

    def test_aci_netflow_vlans_are_valid_encap_values(self) -> None:
        rows = events("stream_netflow.ndjson")
        vlans = {
            row["event"]["ingress_vlan"]
            for row in rows
            if "ingress_vlan" in row["event"]
        }
        self.assertTrue(vlans)
        self.assertTrue(all(1 <= vlan <= 4094 for vlan in vlans))
        self.assertIn(1030, vlans)
        self.assertTrue(any("ingress_vlan" not in row["event"] for row in rows))


if __name__ == "__main__":
    unittest.main()
