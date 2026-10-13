"""Isolated handoff regressions using in-memory rows; no KV writes or resets."""

import copy
import json
import os
import unittest

import lab


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class HandoffRegressionTest(unittest.TestCase):
    def rows(self):
        client = "vm:prod/10.30.40.25"
        pod = "pod:demo-cluster/test-pod"
        frontend = "k8s_service:demo-cluster/shop/checkout-api/10.50.0.20:80"
        base = {
            "adm_row": "conv",
            "scope": "prod",
            "client_ip": "10.30.40.25",
            "server_ip": "10.42.1.20",
            "server_port": 8080,
            "transport": "tcp",
            "flow_source": "netflow",
            "observer": "netflow:leaf",
            "first_seen": 100,
            "last_seen": 101,
            "adm_bfs": 100,
            "adm_bls": 101,
            "adm_ws": 0,
            "adm_we": 500,
            "adm_keep": 1,
            "adm_c_state": "resolved",
            "adm_s_state": "resolved",
            "adm_c_kind": "vm",
            "adm_s_kind": "pod",
            "adm_c_id": client,
            "adm_s_id": pod,
            "adm_s_name": "checkout-api",
            "adm_s_ns": "shop",
            "adm_s_best": json.dumps({"pn": "web", "lbm": "snat"}),
            "adm_conns": "50000@100@101",
            "adm_c_node": json.dumps({"id": client}),
            "adm_s_node": json.dumps({"id": pod}),
        }
        front = dict(
            base,
            tag="front",
            server_ip="10.50.0.20",
            server_port=80,
            adm_s_kind="k8s_service",
            adm_s_id=frontend,
            adm_s_node=json.dumps({"id": frontend}),
        )
        hubble = dict(
            base, tag="hubble", flow_source="hubble", observer="hubble:node-b"
        )
        direct = dict(base, tag="direct")
        later = dict(
            base,
            tag="later",
            first_seen=400,
            last_seen=401,
            adm_bfs=400,
            adm_bls=401,
            adm_conns="50000@400@401",
        )
        backend = {
            "adm_row": "backend",
            "tag": "backend",
            "namespace": "shop",
            "service": "checkout-api",
            "pod_uid": "test-pod",
            "ip": "10.42.1.20",
            "target_port": 8080,
            "node": "node-b",
            "valid_from": 0,
            "port_name": "web",
            "protocol": "tcp",
            "adm_ws": 0,
            "adm_we": 500,
        }
        return [front, hubble, direct, later, backend]

    def run_graph(self, rows):
        for r in rows:
            if r["adm_row"] in ("conv", "xlate", "l7"):
                r["adm_ck"] = "|".join(
                    str(r[k])
                    for k in (
                        "scope",
                        "client_ip",
                        "server_ip",
                        "server_port",
                        "transport",
                    )
                )
        for r in rows:
            if isinstance(r.get("adm_conns"), list):
                r["adm_conns"] = ";".join(r["adm_conns"])
        data = json.dumps(json.dumps(rows))
        return lab.search(
            f'| makeresults format=json data={data} | makemv delim=";" adm_conns | `adm_graph_handoffs("checkout","prod","demo-cluster","shop")`',
            "0",
            "500",
        )

    def basis(self, rows):
        return [r.get("handoff_basis") for r in rows if r.get("adm_row") == "hconn"]

    def test_transport_matches_both_candidate_and_hubble_evidence(self):
        self.assertEqual(
            self.basis(self.run_graph(self.rows())), ["hubble_client_tuple"]
        )
        for tag, field in [("hubble", "transport"), ("backend", "protocol")]:
            with self.subTest(tag=tag):
                rows = self.rows()
                next(r for r in rows if r["tag"] == tag)[field] = "udp"
                self.assertEqual(self.basis(self.run_graph(rows)), [None])

    def test_udp_handoff_positive_control(self):
        rows = self.rows()
        for row in rows:
            if row["adm_row"] == "conv":
                row["transport"] = "udp"
            else:
                row["protocol"] = "udp"
        self.assertEqual(self.basis(self.run_graph(rows)), ["hubble_client_tuple"])

    def test_consumption_keeps_later_connection_and_other_transport(self):
        rows = self.rows()
        udp = dict(rows[2], tag="udp", transport="udp")
        rows.append(udp)
        result = {r.get("tag"): r for r in self.run_graph(rows) if r.get("tag")}
        for tag in ("hubble", "direct"):
            self.assertEqual(result[tag]["adm_consumed"], "1")
        for tag in ("later", "udp"):
            self.assertNotEqual(result[tag]["adm_consumed"], "1")
            self.assertIn("adm_conns", result[tag])

    def test_consumption_handles_point_evidence_and_reexports(self):
        rows = self.rows()
        rows[1]["adm_conns"] = "50000@100.5@100.5"
        rows[2]["adm_conns"] = ["50000@100@180", "50000@180@260"]
        result = {r.get("tag"): r for r in self.run_graph(rows) if r.get("tag")}
        self.assertEqual(result["hubble"]["adm_consumed"], "1")
        self.assertEqual(result["direct"]["adm_consumed"], "1")
        self.assertEqual(result["later"]["adm_consumed"], "0")

    def test_snat_evidence_requires_matching_transport(self):
        for transport in ("tcp", "udp"):
            with self.subTest(transport=transport):
                rows = self.rows()
                rows[1].update(
                    adm_row="xlate",
                    flow_source="hubble_xlate",
                    observer="hubble_xlate:node-a",
                    transport=transport,
                    xlate_ip="10.30.40.30",
                )
                expected = "hubble_xlate" if transport == "tcp" else None
                self.assertEqual(self.basis(self.run_graph(rows)), [expected])

    def test_time_inference_requires_matching_transport(self):
        for transport in ("tcp", "udp"):
            with self.subTest(transport=transport):
                rows = self.rows()
                rows[1].update(
                    flow_source="netflow",
                    observer="netflow:leaf",
                    adm_c_kind="k8s_node",
                    adm_c_name="node-a",
                    adm_c_hn=0,
                    transport=transport,
                )
                expected = "time_inferred" if transport == "tcp" else None
                self.assertEqual(self.basis(self.run_graph(rows)), [expected])

    def test_named_route_matches_service_and_port_together(self):
        for port in ("web", "other"):
            with self.subTest(port=port):
                rows = self.rows()
                rows[0]["adm_s_best"] = json.dumps(
                    {
                        "pn": "web",
                        "lbm": "snat",
                        "ctl": "cilium_ingress",
                        "ownk": "Ingress",
                        "ownn": "entry",
                    }
                )
                route = {
                    "adm_row": "route",
                    "parent_kind": "Ingress",
                    "parent_namespace": "shop",
                    "parent_name": "entry",
                    "backend_namespace": "shop",
                    "backend_service": "checkout-api",
                    "backend_port_name": port,
                    "valid_from": 0,
                    "adm_ws": 0,
                    "adm_we": 500,
                }
                rows.append(route)
                # A second service using "web" must not make the wrong port on checkout-api eligible.
                other = copy.deepcopy(route)
                other.update(backend_service="unrelated", backend_port_name="web")
                rows.append(other)
                expected = "hubble_client_tuple" if port == "web" else None
                self.assertEqual(self.basis(self.run_graph(rows)), [expected])
