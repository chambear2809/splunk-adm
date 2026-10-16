"""End-to-end ACI/ND network metadata checks for the disposable Splunk lab."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import time
import unittest
import uuid

import lab


ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "fixtures" / "raw-aci"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class EndpointNetworkTest(unittest.TestCase):
    """Use isolated observer scopes and public data-layer macros only."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.token = "network-" + uuid.uuid4().hex[:12]
        cls.scope = cls.token
        cls.apic = "198.51.100.50"
        cls.nd = "198.51.100.60"
        cls.start = int(time.time()) - 180
        cls.loaded = 0
        cls.addClassCleanup(cls.cleanup)
        rows = [
            {"observer_kind": "apic", "observer": cls.apic, "scope": cls.scope},
            {"observer_kind": "nd_host", "observer": cls.nd, "scope": cls.scope},
        ]
        payload = json.dumps(json.dumps(rows))
        lab.search(
            f'| makeresults format=json data={payload} '
            '| eval observer_kind=lower(observer_kind), observer=lower(observer), '
            "_key=sha256(json_array(observer_kind, observer)) "
            "| fields _key observer_kind observer scope | outputlookup append=true "
            "key_field=_key adm_observer_scope"
        )

    @classmethod
    def cleanup(cls) -> None:
        import urllib.parse

        query = urllib.parse.urlencode(
            {"query": json.dumps({"scope": cls.scope})}
        )
        for collection in ("adm_ip_identity", "adm_observer_scope"):
            response = lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/{lab.APP}/storage/collections/data/"
                f"{collection}?{query}",
            )
            response.close()

    @staticmethod
    def fixture(name: str) -> list[dict]:
        return [
            json.loads(line)
            for line in (RAW / name).read_text("utf-8").splitlines()
            if line.strip()
        ]

    def isolated(self, event: dict, *, at: int) -> dict:
        row = copy.deepcopy(event)
        row["time"] = at
        row["source"] = self.token
        row["host"] = "network-test"
        row["index"] = "cisco_dc" if row["sourcetype"].startswith("cisco:") else "netflow"
        if row["sourcetype"].startswith("cisco:"):
            row["event"] = row["event"].replace("192.0.2.50", self.apic)
            row["event"] = row["event"].replace("192.0.2.60", self.nd)
        return row

    def load(self, rows: list[dict]) -> None:
        lab._hec_post(("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        self.loaded += len(rows)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            found = lab.search(
                f'index=* source="{self.token}" | stats count', "0", "+10y"
            )
            if found and int(found[0]["count"]) == self.loaded:
                return
            time.sleep(1)
        self.fail("network fixture events did not become searchable")

    def build_identity(self) -> list[dict]:
        return lab.search(
            f'source="{self.token}" `adm_identity_build`',
            self.start - 5,
            self.start + 30,
        )

    def test_apic_relation_and_nd_fallback_are_mac_scoped(self):
        endpoints = self.fixture("aci_class.ndjson")
        aci_ep = next(e for e in endpoints if 'component="fvCEp"' in e["event"])
        relation = next(e for e in endpoints if 'component="fvRsBd"' in e["event"])
        nd = self.fixture("nd_endpoints.ndjson")[0]
        nd["event"] = json.loads(nd["event"])
        nd["event"].update(
            endpointId="network-fallback",
            mac="00:50:56:AA:40:99",
            ip=["10.99.40.99"],
            nodeName="leaf-101",
            displayBd="bd-clients",
            displayEpg="win-clients",
            nd_host=self.nd,
        )
        nd["event"] = json.dumps(nd["event"])
        self.load(
            [
                self.isolated(aci_ep, at=self.start),
                self.isolated(relation, at=self.start),
                self.isolated(nd, at=self.start),
            ]
        )
        summary = self.build_identity()
        self.assertEqual(len(summary), 1)
        identities = lab.search(
            f'| inputlookup adm_ip_identity where scope="{self.scope}" '
            '| table ip entity_kind tenant app_profile epg mac attr_vlan attr_bridge_domain desc'
        )
        apic = next(row for row in identities if row["ip"] == "10.30.40.25")
        self.assertEqual(apic["entity_kind"], "vm")
        self.assertEqual(apic.get("attr_vlan"), "1030")
        self.assertEqual(apic.get("attr_bridge_domain"), "bd-clients")
        fallback = next(row for row in identities if row["ip"] == "10.99.40.99")
        self.assertEqual(fallback["entity_kind"], "endpoint")
        self.assertEqual(fallback.get("attr_bridge_domain"), "bd-clients")
        self.assertNotEqual(apic["mac"], fallback["mac"])

    def test_netflow_rollup_preserves_totals_and_observations(self):
        flows = self.fixture("stream_netflow.ndjson")
        selected = [
            e
            for e in flows
            if e["event"].get("src_ip") == "10.30.40.25"
            and e["event"].get("dest_ip") == "10.50.0.10"
        ][:2]
        for i, row in enumerate(selected):
            row = self.isolated(row, at=self.start + i)
            row["event"]["exporter_ip"] = "198.51.100." + str(71 + i)
            row["event"]["input_snmpidx"] = 436224000 + i
            selected[i] = row
        self.load(selected)
        rows = lab.search(
            f'index=netflow source="{self.token}" | `adm_flows` '
            f'| `adm_conversation_rollup` | where scope="{self.scope}"',
            self.start - 5,
            self.start + 30,
        )
        self.assertTrue(rows)
        rollup = rows[0]
        self.assertEqual(float(rollup["bytes_c2s"]), 3600)
        self.assertEqual(float(rollup["bytes_s2c"]), 0)
        observations = json.loads(rollup["vlan_observations"])
        self.assertIsInstance(observations, list)
        self.assertTrue(observations)
        for observation in observations:
            self.assertIn(observation["position"], {"ingress", "egress"})
            self.assertTrue(1 <= int(observation["vlan"]) <= 4094)
            self.assertEqual(observation["src_ip"], "10.30.40.25")
            if observation.get("interface_index") is None:
                self.assertNotIn("interface_index", observation)

    def test_invalid_relation_states_and_tenant_are_not_promoted(self):
        endpoints = self.fixture("aci_class.ndjson")
        endpoint = next(e for e in endpoints if 'component="fvCEp"' in e["event"])
        relation = next(e for e in endpoints if 'component="fvRsBd"' in e["event"])
        cases = [
            ("10.99.41.1", "00:50:56:AA:41:01", "unformed", self.start),
            ("10.99.41.2", "00:50:56:AA:41:02", "formed", self.start + 500),
            ("10.99.41.3", "00:50:56:AA:41:03", "formed", self.start),
        ]
        rows = []
        for ip, mac, state, relation_time in cases:
            cep = copy.deepcopy(endpoint)
            cep["event"] = cep["event"].replace("10.30.40.25", ip).replace(
                "00:50:56:AA:40:25", mac
            )
            rel = copy.deepcopy(relation)
            rel["event"] = (
                rel["event"]
                .replace("epg-win-clients/rsbd", f"epg-win-clients-{mac[-2:]}/rsbd")
                .replace("uni/tn-shop/BD-bd-clients", "uni/tn-shop/BD-bd-clients")
                .replace('state="formed"', f'state="{state}"')
            )
            if ip.endswith(".3"):
                rel["event"] = rel["event"].replace("uni/tn-shop/", "uni/tn-other/")
            rows.extend(
                [
                    self.isolated(cep, at=self.start),
                    self.isolated(rel, at=relation_time),
                ]
            )
        self.load(rows)
        self.build_identity()
        identities = lab.search(
            f'| inputlookup adm_ip_identity where scope="{self.scope}" '
            '| table ip attr_bridge_domain'
        )
        by_ip = {row["ip"]: row for row in identities}
        for ip, *_ in cases:
            with self.subTest(ip=ip):
                self.assertNotIn("attr_bridge_domain", by_ip.get(ip, {}))

    def test_graph_resolve_keeps_identity_after_metadata_change(self):
        endpoints = self.fixture("aci_class.ndjson")
        aci_ep = next(e for e in endpoints if 'component="fvCEp"' in e["event"])
        relation = next(e for e in endpoints if 'component="fvRsBd"' in e["event"])
        changed = copy.deepcopy(aci_ep)
        changed["event"] = changed["event"].replace('encap="vlan-1030"', 'encap="vlan-1031"')
        self.load(
            [
                self.isolated(aci_ep, at=self.start),
                self.isolated(relation, at=self.start),
                self.isolated(changed, at=self.start + 60),
            ]
        )
        self.build_identity()
        rows = lab.search(
            f'| makeresults | eval adm_row="conv", client_ip="10.30.40.25", '
            f'server_ip="10.50.0.10", server_port=443, transport="tcp", '
            f'scope="{self.scope}", first_seen={self.start + 1}, last_seen={self.start + 61}, '
            f'adm_ws={self.start}, adm_we={self.start + 120} '
            '| `adm_graph_resolve("frontend","demo","network-cluster","shop")` '
            '| table adm_c_state adm_s_state adm_c_id adm_s_id',
            self.start - 5,
            self.start + 130,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["adm_c_state"], "resolved")
        self.assertEqual(rows[0]["adm_s_state"], "none")


if __name__ == "__main__":
    unittest.main()
