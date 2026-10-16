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
        expressions = []
        for d in descriptors:
            descriptor = {
                "vf": 0,
                "ve": 100000,
                "fs": 0,
                "ls": 10000,
                "p": 3,
                "kind": "endpoint",
                "id": d["id"],
                "name": "test",
                "source": d["source"],
                "ek": "ep:test/10.0.0.1/" + d["mac"],
                "mac": d["mac"],
            }
            if "nh" in d:
                descriptor["nh"] = d["nh"]
            if "nhc" in d:
                descriptor["nhc"] = str(d["nhc"])
            # Pass one complete JSON object to Splunk.  This preserves nh as
            # a JSON array and avoids mvappend's single-argument limitation.
            expr = "json(%s)" % json.dumps(
                json.dumps(descriptor, separators=(",", ":"))
            )
            expressions.append(expr)
        desc_expr = (
            expressions[0]
            if len(expressions) == 1
            else "mvappend(" + ",".join(expressions) + ")"
        )
        query = (
            "| makeresults | eval adm_c_desc=%s, adm_bfs=%d, adm_bls=%d, "
            'client_ip="10.0.0.1", scope="test" | `adm_resolve(c,client_ip)` '
            "| table adm_c_state adm_c_node"
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
        self.assertEqual(wildcard.get("attr_bridge_domain"), "nd-bd")
        old = self._descriptor("aci", [])
        old.pop("nh")
        result = self.resolve([old], 1001, 1002)
        self.assertIsNone(result.get("attr_vlan"))
        self.assertIsNone(result.get("attr_bridge_domain"))

    def test_mismatched_mac_keeps_identity_ambiguous(self):
        result = self.resolve(
            [
                self._descriptor("aci", [{"t": 1000, "v": "1030"}], mac="AA"),
                self._descriptor("nd_endpoints", [{"t": 1000, "b": "nd-bd"}], mac="BB"),
            ],
            1001,
            1002,
        )
        self.assertEqual(result.get("state"), "ambiguous")
        self.assertIsNone(result.get("attr_vlan"))
        self.assertIsNone(result.get("attr_bridge_domain"))

    def test_cap_flag_is_retained_without_extrapolating_before_history(self):
        capped = self._descriptor("aci", [{"t": 2000, "v": "1030"}])
        capped["nhc"] = "1"
        result = self.resolve([capped], 1001, 1002)
        self.assertIsNone(result.get("attr_vlan"))
        self.assertEqual(result.get("attr_vlan_status"), "incomplete")
        self.assertEqual(result.get("attr_network_history_capped"), "1")

    @staticmethod
    def _merge_row(samples: list[dict], ip: str = "198.18.0.1") -> str:
        sample_expr = ",".join(
            'json_object("t",%d,"v","%s","b","%s","bd_dn","uni/tn-t/BD-b","bd_tenant","t","source","aci")'
            % (s["t"], s.get("v", "1030"), s.get("b", "bd"))
            for s in samples
        )
        history_expr = (
            sample_expr if len(samples) == 1 else "mvappend(%s)" % sample_expr
        )
        return (
            '| makeresults | eval ip="%s", scope="history-test", entity_kind="endpoint", '
            'entity_id="ep-history", entity_name="history", source="aci", ek="ep:history/%s", '
            'mac="AA", valid_from=0, valid_to=null(), first_seen=0, last_seen=%d, priority=3, '
            "network_history=%s"
        ) % (ip, ip, max(s["t"] for s in samples), history_expr)

    def merge_history(self, rows: list[list[dict]]) -> dict:
        query = self._merge_row(rows[0])
        for samples in rows[1:]:
            query += " | append [ %s ]" % self._merge_row(samples)
        query += ' | `adm_identity_merge` | eval nh_json=json_extract(desc,"nh"), nh_items=json_array_to_mv(nh_json) | table desc nh_json nh_items attr_network_history_capped'
        result = self.lab.search(query)
        self.assertEqual(len(result), 1, result)
        return result[0]

    def test_identity_merge_persists_true_array_and_caps_newest_samples(self):
        samples = [{"t": 1000 + 10 * i} for i in range(520)]
        row = self.merge_history([samples])
        parsed = json.loads(row["desc"])
        self.assertIsInstance(parsed.get("nh"), list)
        self.assertEqual(len(parsed["nh"]), 512)
        self.assertEqual(parsed["nh"][0]["t"], 1080)
        self.assertEqual(parsed["nh"][-1]["t"], 6190)
        self.assertEqual(row.get("attr_network_history_capped"), "1")

    def test_identity_merge_late_order_and_duplicates_are_idempotent(self):
        newer = [{"t": 3000, "v": "1030", "b": "bd"}]
        older = [{"t": 1000, "v": "1020", "b": "bd-old"}]
        row = self.merge_history([newer, older, newer])
        parsed = json.loads(row["desc"])
        self.assertEqual([sample["t"] for sample in parsed["nh"]], [1000, 3000])
        self.assertEqual(parsed["nh"][-1]["v"], "1030")

    def test_stored_array_survives_late_ingestion_and_replay(self):
        import uuid
        import urllib.parse
        import time

        scope = "network-history-" + uuid.uuid4().hex

        def cleanup():
            query = urllib.parse.urlencode({"query": json.dumps({"scope": scope})})
            self.lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity?"
                + query,
            ).close()

        self.addCleanup(cleanup)

        def persist(samples):
            query = self._merge_row(samples).replace(
                'scope="history-test"', f'scope="{scope}"'
            )
            query += " | `adm_identity_merge` | fields _key ip scope entity_kind entity_id entity_name source ek mac valid_from valid_to valid_end first_seen last_seen priority desc network_history attr_network_history_capped | outputlookup append=true key_field=_key adm_ip_identity | table desc network_history last_seen"
            return self.lab.search(query)[0]

        persist([{"t": 3000, "v": "1030"}])
        late = persist([{"t": 1000, "v": "1020"}])
        replay = persist([{"t": 3000, "v": "1030"}])
        self.assertEqual(
            json.loads(late["network_history"]), json.loads(replay["network_history"])
        )
        self.assertEqual(
            [r["t"] for r in json.loads(replay["desc"])["nh"]], [1000, 3000]
        )
        self.assertEqual(float(replay["last_seen"]), 3000)
        retained = persist([{"t": 700000, "v": "1040"}])
        self.assertEqual(
            [r["t"] for r in json.loads(retained["network_history"])], [700000]
        )

    def test_separate_builds_mark_cross_builder_network_changes_varies(self):
        import uuid
        import urllib.parse

        scope = "network-change-" + uuid.uuid4().hex
        query = urllib.parse.urlencode({"query": json.dumps({"scope": scope})})
        self.addCleanup(
            lambda: self.lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity?"
                + query,
            ).close()
        )

        def persist(sample):
            spl = self._merge_row([sample]).replace(
                'scope="history-test"', f'scope="{scope}"'
            )
            spl += " | `adm_identity_merge` | fields _key ip scope entity_kind entity_id entity_name source ek mac priority valid_from valid_to valid_end first_seen last_seen desc attr_vlan attr_bridge_domain attr_vlan_status attr_bridge_domain_status network_history attr_network_history_capped | outputlookup append=true key_field=_key adm_ip_identity | table attr_vlan attr_bridge_domain attr_vlan_status attr_bridge_domain_status desc network_history"
            return self.lab.search(spl)[0]

        base = int(time.time())
        persist({"t": base, "v": "1030", "b": "bd-a"})
        changed = persist({"t": base + 100, "v": "1040", "b": "bd-b"})
        replay = persist({"t": base + 200, "v": "1030", "b": "bd-a"})
        for row in (changed, replay):
            self.assertNotIn("attr_vlan", row)
            self.assertNotIn("attr_bridge_domain", row)
            self.assertEqual(row.get("attr_vlan_status"), "varies")
            self.assertEqual(row.get("attr_bridge_domain_status"), "varies")
        self.assertEqual(
            [sample["t"] for sample in json.loads(replay["network_history"])],
            [base, base + 100, base + 200],
        )

    def test_graph_aggregation_keeps_missing_legacy_period_incomplete(self):
        old = self._descriptor("aci", [])
        old.pop("nh")
        new = self._descriptor("aci", [{"t": 1000, "v": "1030", "b": "bd"}])
        query = (
            "| makeresults count=2 | streamstats count AS seq | eval adm_c_desc=if(seq==1, "
            + json.dumps(json.dumps(old))
            + ", "
            + json.dumps(json.dumps(new))
            + '), adm_bfs=1001, adm_bls=1002, client_ip="10.0.0.1", scope="test" '
            '| `adm_resolve(c,client_ip)` | eval adm_row="node_src", adm_node_out="1#".adm_c_node '
            '| append [| makeresults | eval adm_row="span", adm_span=json_object("root",1)] '
            '| `adm_graph_output("frontend","demo","demo-cluster","shop")` '
            '| where row_type="node"'
        )
        rows = self.lab.search(query)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["attr_vlan_status"], "incomplete")
        self.assertEqual(rows[0]["attr_bridge_domain_status"], "incomplete")
        self.assertNotIn("attr_vlan", rows[0])
        self.assertNotIn("attr_bridge_domain", rows[0])

    def test_full_history_expansion_preserves_all_conversation_rows(self):
        desc = self._descriptor(
            "aci", [{"t": 1000 + 10 * i, "v": "1030", "b": "bd"} for i in range(512)]
        )
        query = (
            "| makeresults count=20 | eval adm_c_desc="
            + json.dumps(json.dumps(desc))
            + ', adm_bfs=5000, adm_bls=5100, client_ip="10.0.0.1", scope="test" '
            '| `adm_resolve(c,client_ip)` | stats count count(eval(adm_c_network_vlan=="1030")) AS confirmed'
        )
        rows = self.lab.search(query)
        self.assertEqual(rows, [{"count": "20", "confirmed": "20"}])

    def test_incomplete_relationship_read_cannot_close_a_stored_owner(self):
        import uuid
        import urllib.parse

        scope = "network-guard-" + uuid.uuid4().hex
        query = urllib.parse.urlencode({"query": json.dumps({"scope": scope})})
        self.addCleanup(
            lambda: self.lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity?"
                + query,
            ).close()
        )
        base = (
            '| makeresults | eval ip="198.18.1.1", scope="%s", source="k8s_pods", '
            'entity_kind="pod", entity_id="old", cluster="guard", ek="pod:guard/old", '
            "priority=1, valid_from=1000, first_seen=1000, last_seen=1000"
        ) % scope
        self.lab.search(
            base
            + " | `adm_identity_merge` | fields _key ip scope source entity_kind entity_id cluster ek priority valid_from first_seen last_seen desc | outputlookup append=true key_field=_key adm_ip_identity"
        )
        rows = self.lab.search(
            base
            + ' | eval entity_id="new", ek="pod:guard/new", valid_from=2000, first_seen=2000, last_seen=2000, adm_network_complete=0 '
            "| `adm_identity_merge` | table entity_id adm_close adm_write valid_to"
        )
        self.assertEqual({row["entity_id"] for row in rows}, {"old", "new"})
        self.assertTrue(all(row["adm_write"] == "0" for row in rows), rows)
        self.assertTrue(all(row["adm_close"] == "0" for row in rows), rows)
        self.assertTrue(all("valid_to" not in row for row in rows), rows)
