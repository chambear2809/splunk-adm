"""Installed SPL checks for the connection-level service scope stage."""

import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class ServiceScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab

    def run_scope(self, competing=False):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {"adm_row": "binding", "adm_service_mode": 1},
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_c_kind": "pod",
                "adm_c_uid": "p1",
                "adm_c_id": "pod:c/p1",
                "adm_s_id": "ip:dependency",
                "first_seen": 110,
                "last_seen": 120,
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_c_kind": "pod",
                "adm_c_uid": "p2",
                "adm_c_id": "pod:c/p2",
                "adm_s_id": "ip:other",
                "first_seen": 110,
                "last_seen": 120,
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_c_kind": "pod",
                "adm_c_uid": "p1",
                "adm_c_id": "pod:c/p1",
                "adm_s_id": "ip:expired",
                "first_seen": 3701,
                "last_seen": 3702,
            },
            {
                "adm_row": "hconn",
                "adm_service_mode": 1,
                "adm_targets": "pod:c/p1",
                "adm_ct": 110,
                "adm_cend": 120,
                "adm_fe_cid": "ip:client",
                "adm_fe_id": "k8s_service:c/shop/vip",
                "server_port": "80",
                "transport": "tcp",
                "handoff_basis": "hubble_client_tuple",
            },
        ]
        if competing:
            events.append(
                {
                    "adm_row": "service_competing",
                    "adm_service_mode": 1,
                    "adm_service_binding": "p1|105|125",
                }
            )
        payload = json.dumps(json.dumps(events))
        return self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | fields adm_row adm_c_id adm_s_id adm_keep adm_service_omitted",
            "0",
            "now",
        )

    def test_selected_interval_and_handoff_only(self):
        rows = self.run_scope()
        kept = {r.get("adm_s_id") for r in rows if str(r.get("adm_keep")) == "1"}
        self.assertEqual(kept, {"ip:dependency"})
        self.assertEqual(sum(r.get("adm_row") == "hconn" for r in rows), 1)
        self.assertTrue(any(str(r.get("adm_service_omitted")) == "1" for r in rows))

    def test_real_schedule_uses_prior_binding_not_span_duration(self):
        # Root spans are 1 ms observations; the later flow is not inside them.
        rows = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|60.001",
            },
            {
                "adm_row": "binding",
                "adm_service_mode": 1,
                "adm_service_witness": ["pod:c/p1|60", "pod:c/p1|960"],
            },
        ]
        for t in (150, 151, 600, 930):
            rows.append(
                {
                    "adm_row": "conv",
                    "adm_service_mode": 1,
                    "adm_keep": 1,
                    "adm_c_kind": "pod",
                    "adm_c_id": "pod:c/p1",
                    "adm_s_id": f"ip:{t}",
                    "first_seen": t,
                    "last_seen": t + 0.001,
                }
            )
        # A future-only witness cannot authorize the earlier flow.
        rows.extend(
            [
                {
                    "adm_row": "span",
                    "adm_service_mode": 1,
                    "adm_service_span": "pod:c/future|960.001",
                },
                {
                    "adm_row": "conv",
                    "adm_service_mode": 1,
                    "adm_keep": 1,
                    "adm_c_kind": "pod",
                    "adm_c_id": "pod:c/future",
                    "adm_s_id": "ip:future",
                    "first_seen": 930,
                    "last_seen": 930.001,
                },
            ]
        )
        payload = json.dumps(json.dumps(rows))
        found = self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | fields adm_row adm_s_id adm_keep",
            "0",
            "now",
        )
        kept = {row.get("adm_s_id") for row in found if str(row.get("adm_keep")) == "1"}
        self.assertEqual(kept, {"ip:150", "ip:151", "ip:600", "ip:930"})

    def test_only_selected_handoff_can_consume_xlate_leg(self):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {
                "adm_row": "hconn",
                "adm_service_mode": 1,
                "adm_targets": "pod:c/p1",
                "adm_ct": 110,
                "adm_cend": 120,
                "adm_fe_cid": "ip:client",
                "adm_fe_id": "k8s_service:c/shop/vip",
                "server_port": "80",
                "transport": "tcp",
                "handoff_basis": "hubble_xlate",
                "adm_mX": "51000|110|10.0.0.1:80|pod:c/p1|node-a|192.0.2.1|120|tcp",
            },
            {
                "adm_row": "xlate",
                "adm_service_mode": 1,
                "adm_xleg": "192.0.2.1|51000|110|120|10.0.0.1:80|tcp",
            },
            {
                "adm_row": "xlate",
                "adm_service_mode": 1,
                "adm_xleg": "192.0.2.2|51001|110|120|10.0.0.2:80|tcp",
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | search adm_row=xlate | fields adm_xleg",
            "0",
            "now",
        )
        self.assertEqual(
            [r.get("adm_xleg") for r in rows if r.get("adm_xleg")],
            ["192.0.2.1|51000|110|120|10.0.0.1:80|tcp"],
        )

    def test_frontend_requires_unique_fully_valid_selected_backend(self):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_fe": 1,
                "adm_c_id": "ip:client",
                "adm_s_id": "k8s_service:c/shop/owned",
                "first_seen": 110,
                "last_seen": 120,
                "adm_fe_cands": "shop/owned|p1|10.0.0.1|80|node-a|100|130||tcp",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_fe": 1,
                "adm_c_id": "ip:client",
                "adm_s_id": "k8s_service:c/shop/expired",
                "first_seen": 110,
                "last_seen": 120,
                "adm_fe_cands": "shop/owned|p1|10.0.0.1|80|node-a|100|115||tcp",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_fe": 1,
                "adm_c_id": "ip:client",
                "adm_s_id": "k8s_service:c/shop/shared",
                "first_seen": 110,
                "last_seen": 120,
                "adm_fe_cands": "shop/owned|p1|10.0.0.1|80|node-a|100|130||tcp;shop/owned|p2|10.0.0.2|80|node-b|100|130||tcp",
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f'| makeresults format=json data={payload} | eval adm_fe_cands=if(like(adm_fe_cands,"%;%"),split(adm_fe_cands,";"),adm_fe_cands) | `adm_graph_service_handoff_scope` | search adm_row=conv | eval adm_candidate_count=mvcount(adm_fe_cands) | fields adm_s_id adm_keep adm_candidate_count adm_fe_cands adm_service_fe_uids adm_service_fe_uid adm_service_owned_fe adm_service_frontend adm_service_proof adm_service_peer',
            "0",
            "now",
        )
        shared = next(
            r for r in rows if r.get("adm_s_id") == "k8s_service:c/shop/shared"
        )
        self.assertEqual(int(shared["adm_candidate_count"]), 2, shared)
        kept = {r.get("adm_s_id") for r in rows if str(r.get("adm_keep")) == "1"}
        self.assertEqual(kept, {"k8s_service:c/shop/owned"}, rows)

    def test_valid_server_survives_stale_client_affinity(self):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/client|5000",
            },
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/server|100",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_c_kind": "pod",
                "adm_s_kind": "pod",
                "adm_c_id": "pod:c/client",
                "adm_s_id": "pod:c/server",
                "first_seen": 110,
                "last_seen": 120,
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | search adm_row=conv | fields adm_keep",
            "0",
            "now",
        )
        self.assertEqual(str(rows[0].get("adm_keep")), "1")

    def test_singleton_frontend_matches_complete_native_conversation_key(self):
        native_key = "conv|scope|10.0.0.1|10.0.0.2|80|tcp|100"
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {
                "adm_row": "hconn",
                "adm_service_mode": 1,
                "adm_targets": "pod:c/p1",
                "adm_ct": 110,
                "adm_cend": 120,
                "adm_cport": "51000",
                "adm_dk": native_key,
                "adm_fe_cid": "ip:client",
                "adm_fe_id": "k8s_service:c/shop/vip",
                "server_port": "80",
                "transport": "tcp",
                "handoff_basis": "hubble_client_tuple",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_ck": native_key,
                "adm_c_id": "ip:client",
                "adm_s_id": "k8s_service:c/shop/vip",
                "server_port": "80",
                "transport": "tcp",
                "first_seen": 110,
                "last_seen": 120,
                "adm_conns": "51000@110@120",
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | search adm_row=conv | fields adm_keep",
            "0",
            "now",
        )
        self.assertEqual(str(rows[0].get("adm_keep")), "1")

    def test_mixed_frontend_connections_are_not_partially_counted(self):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {
                "adm_row": "hconn",
                "adm_service_mode": 1,
                "adm_targets": "pod:c/p1",
                "adm_ct": 110,
                "adm_cend": 120,
                "adm_cport": "51000",
                "adm_dk": "conn-key",
                "adm_fe_cid": "ip:client",
                "adm_fe_id": "k8s_service:c/shop/vip",
                "server_port": "80",
                "transport": "tcp",
                "handoff_basis": "hubble_client_tuple",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_ck": "conn-key",
                "adm_c_id": "ip:client",
                "adm_s_id": "k8s_service:c/shop/vip",
                "server_port": "80",
                "transport": "tcp",
                "first_seen": 110,
                "last_seen": 120,
                "adm_conns": "51000@110@120;51001@110@120",
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f'| makeresults format=json data={payload} | eval adm_conns=if(like(adm_conns,"%;%"),split(adm_conns,";"),adm_conns) | `adm_graph_service_handoff_scope` | search adm_row=conv | fields adm_keep adm_service_omitted',
            "0",
            "now",
        )
        self.assertEqual(str(rows[0].get("adm_keep")), "0")
        self.assertEqual(str(rows[0].get("adm_service_omitted")), "1")

    def test_peer_context_requires_two_prior_resolved_root_observations(self):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_s_kind": "pod",
                "adm_s_id": "pod:c/p1",
                "adm_c_id": "ip:client",
                "first_seen": 110,
                "last_seen": 120,
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_c_kind": "pod",
                "adm_c_id": "pod:c/p1",
                "adm_s_id": "ip:dependency",
                "first_seen": 110,
                "last_seen": 120,
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_peer": 1,
                "adm_c_state": "resolved",
                "adm_s_state": "resolved",
                "adm_c_id": "ip:client",
                "adm_s_id": "ip:dependency",
                "first_seen": 130,
                "last_seen": 140,
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_peer": 1,
                "adm_c_state": "resolved",
                "adm_s_state": "resolved",
                "adm_capped": 1,
                "adm_c_id": "ip:client",
                "adm_s_id": "ip:dependency",
                "first_seen": 130,
                "last_seen": 140,
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_peer": 1,
                "adm_c_state": "resolved",
                "adm_s_state": "resolved",
                "adm_c_id": "ip:client",
                "adm_s_id": "ip:dependency",
                "first_seen": 4000,
                "last_seen": 4010,
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | search adm_peer=1 | fields adm_keep adm_service_peer",
            "0",
            "now",
        )
        self.assertEqual(sum(str(r.get("adm_service_peer")) == "1" for r in rows), 1)
        self.assertEqual(sum(str(r.get("adm_keep")) == "1" for r in rows), 1)

    def test_capped_identity_never_qualifies_root(self):
        events = [
            {
                "adm_row": "span",
                "adm_service_mode": 1,
                "adm_service_span": "pod:c/p1|100",
            },
            {
                "adm_row": "conv",
                "adm_service_mode": 1,
                "adm_keep": 1,
                "adm_c_kind": "pod",
                "adm_c_id": "pod:c/p1",
                "adm_s_id": "ip:peer",
                "adm_capped": 1,
                "first_seen": 110,
                "last_seen": 120,
            },
        ]
        payload = json.dumps(json.dumps(events))
        rows = self.lab.search(
            f"| makeresults format=json data={payload} | `adm_graph_service_handoff_scope` | search adm_row=conv | fields adm_keep adm_service_omitted",
            "0",
            "now",
        )
        self.assertEqual(str(rows[0].get("adm_keep")), "0")
        self.assertEqual(str(rows[0].get("adm_service_omitted")), "1")

    def test_shared_pod_fails_closed(self):
        rows = self.run_scope(competing=True)
        self.assertFalse(any(str(r.get("adm_keep")) == "1" for r in rows))
        self.assertFalse(any(r.get("adm_row") == "hconn" for r in rows))
        self.assertTrue(any(str(r.get("adm_service_omitted")) == "1" for r in rows))


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1"
    and os.environ.get("ADM_SERVICE_GRAPH_FIXTURE_CAPTURE"),
    "requires the original scenario seeded in the exclusive lab and its capture path",
)
class ActualScenarioGraphTest(unittest.TestCase):
    """Check the selected-service contract against the original replayed facts."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        capture = json.loads(
            Path(os.environ["ADM_SERVICE_GRAPH_FIXTURE_CAPTURE"]).read_text()
        )
        cls.capture = capture
        cls.app = capture["manifest"]["application"]
        cls.anchor = int(capture["manifest"]["anchor_epoch"])
        baseline = capture["results"]["graph.baseline"]["rows"]
        cls.pods = {}
        for row in baseline:
            if row.get("relationship") == "runs_on":
                service = row["source"].split("/")[-2]
                cls.pods[service] = row["target"]
        if not {"checkout", "inventory", "pricing"} <= cls.pods.keys():
            raise AssertionError(
                "original capture does not contain all three Pod bindings"
            )

    def graph(self, service, begin, end):
        app = self.app
        args = f'"{service}","{app["environment"]}","{app["cluster"]}","{app["namespace"]}"'
        return self.lab.search(
            f"| search `adm_graph_service_v2({args})`",
            str(self.anchor + begin),
            str(self.anchor + end),
        )

    def test_each_service_baseline_and_child_later_phases(self):
        for service in ("inventory", "pricing"):
            with self.subTest(service=service):
                baseline = self.graph(service, 0, 300)
                network = [
                    r for r in baseline if r.get("relationship") == "communicates_with"
                ]
                self.assertEqual(len(network), 1, network)
                self.assertEqual(network[0].get("target"), self.pods[service])
                owners = [
                    r.get("target")
                    for r in baseline
                    if r.get("relationship") == "runs_on"
                ]
                self.assertEqual(owners, [self.pods[service]])
                for begin, end in ((300, 420), (420, 900), (900, 1200)):
                    later = self.graph(service, begin, end)
                    self.assertFalse(
                        [
                            r
                            for r in later
                            if r.get("relationship")
                            in {"communicates_with", "forwards_to"}
                        ],
                        later,
                    )
                    meta = next(r for r in later if r.get("row_type") == "meta")
                    self.assertEqual(int(meta["conversations_in_scope"]), 0)

    def test_legacy_namespace_graph_retains_original_edges(self):
        app = self.app
        args = (
            f'"checkout","{app["environment"]}","{app["cluster"]}","{app["namespace"]}"'
        )
        for phase, begin, end in (
            ("baseline", 0, 300),
            ("change", 300, 420),
            ("impact", 420, 900),
            ("recovery", 900, 1200),
        ):
            with self.subTest(phase=phase):
                actual = self.lab.search(
                    f"| search `adm_graph_v2({args})`",
                    str(self.anchor + begin),
                    str(self.anchor + end),
                )
                original = self.capture["results"][f"graph.{phase}"]["rows"]
                fields = (
                    "id",
                    "source",
                    "target",
                    "relationship",
                    "count",
                    "bytes",
                    "acl_action",
                    "acl_permits",
                    "acl_drops",
                    "handoff_basis",
                    "client_handoff_coverage",
                    "client_handoff_connections",
                    "client_handoff_determined",
                    "client_handoff_unresolved",
                )

                def normalize(rows):
                    return sorted(
                        tuple(str(row.get(field, "")) for field in fields)
                        for row in rows
                        if row.get("row_type") == "edge"
                        and row.get("relationship")
                        in {"communicates_with", "forwards_to", "runs_on"}
                    )

                self.assertEqual(normalize(actual), normalize(original))

    def test_checkout_baseline_and_impact(self):
        baseline = self.graph("checkout", 0, 300)
        edges = [r for r in baseline if r.get("row_type") == "edge"]
        direct = [r for r in edges if r.get("relationship") == "communicates_with"]
        old = self.capture["results"]["graph.baseline"]["rows"]
        forwarded = {
            r.get("source")
            for r in old
            if r.get("relationship") == "forwards_to"
            and r.get("target") == self.pods["checkout"]
        }
        expected = {
            (r.get("source"), r.get("target"))
            for r in old
            if r.get("relationship") == "communicates_with"
            and (
                r.get("source") == self.pods["checkout"]
                or r.get("target") == self.pods["checkout"]
                or r.get("target") in forwarded
            )
        }
        self.assertEqual({(r.get("source"), r.get("target")) for r in direct}, expected)
        for target in (self.pods["inventory"], self.pods["pricing"]):
            self.assertIn((self.pods["checkout"], target), expected)
        for frontend in forwarded:
            self.assertTrue(
                any(
                    r.get("relationship") == "forwards_to"
                    and r.get("source") == frontend
                    and r.get("target") == self.pods["checkout"]
                    for r in edges
                )
            )
            inbound = next(r for r in direct if r.get("target") == frontend)
            original_inbound = next(
                r
                for r in old
                if r.get("relationship") == "communicates_with"
                and r.get("source") == inbound.get("source")
                and r.get("target") == frontend
            )
            for field in (
                "client_handoff_coverage",
                "client_handoff_connections",
                "client_handoff_determined",
                "client_handoff_unresolved",
            ):
                self.assertEqual(
                    str(inbound.get(field, "")),
                    str(original_inbound.get(field, "")),
                    (field, inbound),
                )
            receipts = json.loads(inbound.get("client_handoffs", "[]"))
            self.assertTrue(
                any(
                    record.get("target") == self.pods["checkout"]
                    and record.get("basis")
                    in {"hubble_client_tuple", "hubble_xlate", "l7_forwarded_for"}
                    and int(record.get("connections", 0)) > 0
                    for record in receipts
                ),
                inbound,
            )
        meta = next(r for r in baseline if r.get("row_type") == "meta")
        self.assertEqual(int(meta["conversations_in_scope"]), len(expected))
        node_ids = {r.get("id") for r in baseline if r.get("row_type") == "node"}
        self.assertTrue(
            all(
                r.get("target") in node_ids
                for r in edges
                if r.get("relationship") == "traffic_observation"
            )
        )
        impact = self.graph("checkout", 420, 900)
        impact_direct = {
            (r.get("source"), r.get("target"))
            for r in impact
            if r.get("relationship") == "communicates_with"
        }
        original = self.capture["results"]["graph.impact"]["rows"]
        expected_impact = {
            (r.get("source"), r.get("target"))
            for r in original
            if r.get("relationship") == "communicates_with"
            and (
                r.get("source") == self.pods["checkout"]
                or "/checkout-api/" in str(r.get("target", ""))
            )
        }
        self.assertEqual(impact_direct, expected_impact)
        for phase, begin, end in (("change", 300, 420), ("recovery", 900, 1200)):
            with self.subTest(phase=phase):
                actual = self.graph("checkout", begin, end)
                original_rows = self.capture["results"][f"graph.{phase}"]["rows"]
                expected_pairs = {
                    (r.get("source"), r.get("target"))
                    for r in original_rows
                    if r.get("relationship") == "communicates_with"
                    and (
                        r.get("source") == self.pods["checkout"]
                        or "/checkout-api/" in str(r.get("target", ""))
                    )
                }
                actual_pairs = {
                    (r.get("source"), r.get("target"))
                    for r in actual
                    if r.get("relationship") == "communicates_with"
                }
                self.assertEqual(actual_pairs, expected_pairs)
                expected_forward = {
                    (r.get("source"), r.get("target"))
                    for r in original_rows
                    if r.get("relationship") == "forwards_to"
                    and r.get("target") == self.pods["checkout"]
                    and r.get("confidence") == "observed"
                }
                actual_forward = {
                    (r.get("source"), r.get("target"))
                    for r in actual
                    if r.get("relationship") == "forwards_to"
                }
                self.assertEqual(actual_forward, expected_forward)
                phase_meta = next(r for r in actual if r.get("row_type") == "meta")
                self.assertEqual(
                    int(phase_meta["conversations_in_scope"]), len(expected_pairs)
                )
        if self.capture["manifest"]["variant_id"] == "b-aci-policy":
            self.assertTrue(
                any(
                    int(r.get("acl_drops", 0)) > 0
                    for r in impact
                    if r.get("relationship") == "communicates_with"
                ),
                impact,
            )
        if self.capture["manifest"]["variant_id"] == "a-nat-boundary":
            self.assertTrue(
                any(
                    r.get("nat_observations")
                    for r in impact
                    if r.get("relationship") == "communicates_with"
                ),
                impact,
            )
