"""Live functional checks for V2 per-client Service handoff evidence."""

from __future__ import annotations

import json
import os
import unittest

import lab


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoClientHandoffsTest(unittest.TestCase):
    """Exercise the installed V2 post-handoff macros with normalized stage rows."""

    cluster = "handoff-cluster"
    frontend = "k8s_service:handoff-cluster/shop/checkout-api/10.50.0.20:80"

    def _edge(self, client: str, *, port: int = 80, transport: str = "tcp") -> dict:
        return {
            "adm_row": "edge",
            "relationship": "communicates_with",
            "source": client,
            "target": self.frontend,
            "server_port": port,
            "transport": transport,
            # Deliberately unrelated to the number of represented connections.
            "count": 901,
        }

    def _hconn(
        self,
        client: str,
        cid: str,
        target: str | None,
        *,
        port: int = 80,
        transport: str = "tcp",
        basis: str | None = "hubble_client_tuple",
        via: str = "node-a",
        observer: str = "node-a",
        incomplete: int = 0,
        backend_capped: int = 0,
        scope_capped: int = 0,
    ) -> dict:
        row = {
            "adm_row": "hconn",
            "adm_fe_cid": client,
            "adm_fe_id": self.frontend,
            "adm_cid": cid,
            "scope": "scope-a",
            "server_port": port,
            "transport": transport,
            "via_node": via,
            # The installed handoff-input stage supplies this marker. Tests of
            # the post-stage macro state it explicitly rather than assuming it.
            "adm_v2_handoff_input_incomplete": incomplete,
            "adm_ecapped": backend_capped,
            "adm_scope_capped": scope_capped,
        }
        if target is not None:
            row["adm_targets"] = target
        if basis is not None:
            row["handoff_basis"] = basis
        if observer:
            row["adm_match"] = (
                f"tuple|51000|10.42.0.8|{target or 'pod:else/none'}|{observer}|100|tcp"
            )
        return row

    def _run(self, rows: list[dict]) -> list[dict]:
        payload = json.dumps(json.dumps(rows, separators=(",", ":")))
        return lab.search(
            f"| makeresults format=json data={payload} "
            "| `adm_graph_client_handoffs_v2` "
            "| table adm_row source target server_port transport count "
            "client_handoff_coverage client_handoff_connections "
            "client_handoff_determined client_handoff_unresolved client_handoffs",
            "0",
            "+10y",
        )

    @staticmethod
    def _edge_rows(rows: list[dict]) -> dict[tuple, dict]:
        return {
            (
                row.get("source"),
                row.get("target"),
                int(row["server_port"]),
                row.get("transport"),
            ): row
            for row in rows
            if row.get("adm_row") == "edge"
        }

    @staticmethod
    def _records(edge: dict) -> list[dict]:
        value = edge.get("client_handoffs", "[]")
        return json.loads(value) if isinstance(value, str) else value

    def test_exact_client_frontend_port_transport_and_target_observer_partition(self):
        client_a = "vm:scope-a/10.30.0.11"
        client_b = "vm:scope-a/10.30.0.12"
        pod_a = "pod:handoff-cluster/pod-a"
        pod_b = "pod:handoff-cluster/pod-b"
        rows = [
            self._edge(client_a),
            self._edge(client_b),
            self._edge(client_a, port=8080),
            self._edge(client_a, transport="udp"),
            self._hconn(client_a, "a-1", pod_a, via="node-a", observer="node-a"),
            self._hconn(client_b, "b-1", pod_b, via="node-b", observer="node-b"),
            self._hconn(client_a, "a-8080", pod_b, port=8080),
            self._hconn(client_a, "a-udp", pod_a, transport="udp"),
        ]

        edges = self._edge_rows(self._run(rows))
        self.assertEqual(len(edges), 4)
        by_key = {(key[0], key[2], key[3]): row for key, row in edges.items()}
        a_tcp = by_key[(client_a, 80, "tcp")]
        b_tcp = by_key[(client_b, 80, "tcp")]
        a_alt_port = by_key[(client_a, 8080, "tcp")]
        a_udp = by_key[(client_a, 80, "udp")]
        self.assertEqual(a_tcp["client_handoff_coverage"], "complete")
        self.assertEqual(b_tcp["client_handoff_coverage"], "complete")
        self.assertEqual(self._records(a_tcp)[0]["target"], pod_a)
        self.assertEqual(self._records(b_tcp)[0]["target"], pod_b)
        self.assertEqual(self._records(a_tcp)[0]["observers"], ["hubble:node-a"])
        self.assertEqual(self._records(b_tcp)[0]["observers"], ["hubble:node-b"])
        self.assertEqual(self._records(a_alt_port)[0]["target"], pod_b)
        self.assertEqual(self._records(a_udp)[0]["target"], pod_a)
        for edge in (a_tcp, b_tcp, a_alt_port, a_udp):
            self.assertEqual(int(edge["client_handoff_connections"]), 1)
            self.assertEqual(int(edge["count"]), 901)

    def test_mixed_basis_same_backend_keeps_separate_counts(self):
        client = "vm:scope-a/10.30.0.21"
        pod = "pod:handoff-cluster/pod-a"
        rows = [
            self._edge(client),
            self._hconn(client, "good", pod, basis="hubble_xlate"),
            self._hconn(client, "other", pod, basis="hubble_client_tuple"),
            self._hconn(
                client,
                "inferred",
                pod,
                basis="time_inferred",
                observer="",
                via="node-b",
            ),
        ]

        edge = self._edge_rows(self._run(rows))[(client, self.frontend, 80, "tcp")]
        records = self._records(edge)
        self.assertEqual(edge["client_handoff_coverage"], "complete")
        self.assertEqual(
            (
                int(edge["client_handoff_connections"]),
                int(edge["client_handoff_determined"]),
                int(edge["client_handoff_unresolved"]),
            ),
            (3, 3, 0),
        )
        self.assertEqual(
            {(item["target"], item["basis"], item["connections"]) for item in records},
            {
                (pod, "hubble_xlate", 1),
                (pod, "hubble_client_tuple", 1),
                (pod, "time_inferred", 1),
            },
        )

    def test_service_handoff_metadata_preserves_all_produced_source_identities(self):
        # adm_resolve can retain an unresolved/ambiguous address or resolve a
        # pod, node, or node proxy. Backend evidence does not change that source
        # identity; every inbound Service edge still receives handoff metadata.
        sources = (
            "ip:scope-a/10.30.0.22",
            "ip:scope-a/10.30.0.23",
            "pod:handoff-cluster/client-pod",
            "node:handoff-cluster/client-node",
            "k8s_node_proxy:handoff-cluster/client-node",
        )
        pod = "pod:handoff-cluster/pod-a"
        rows = [
            row
            for position, source in enumerate(sources)
            for row in (
                self._edge(source),
                self._hconn(source, f"source-kind-{position}", pod),
            )
        ]

        edges = self._edge_rows(self._run(rows))
        self.assertEqual({key[0] for key in edges}, set(sources))
        for source in sources:
            with self.subTest(source=source):
                edge = edges[(source, self.frontend, 80, "tcp")]
                self.assertEqual(edge["source"], source)
                self.assertEqual(edge["client_handoff_coverage"], "complete")
                self.assertEqual(int(edge["client_handoff_determined"]), 1)
                self.assertEqual(self._records(edge)[0]["target"], pod)

    def test_conflicting_targets_for_one_connection_fail_singleton_guard(self):
        client = "vm:scope-a/10.30.0.31"
        rows = [
            self._edge(client),
            self._hconn(client, "same-cid", "pod:handoff-cluster/pod-a"),
            self._hconn(client, "same-cid", "pod:handoff-cluster/pod-b"),
        ]

        edge = self._edge_rows(self._run(rows))[(client, self.frontend, 80, "tcp")]
        self.assertEqual(edge["client_handoff_coverage"], "unresolved")
        self.assertEqual(
            (
                int(edge["client_handoff_connections"]),
                int(edge["client_handoff_determined"]),
                int(edge["client_handoff_unresolved"]),
            ),
            (1, 0, 1),
        )
        self.assertEqual(self._records(edge), [])

    def test_unsupported_basis_and_input_incompleteness_fail_closed(self):
        client = "vm:scope-a/10.30.0.41"
        pod = "pod:handoff-cluster/pod-a"
        for marker, basis in ((0, "invented_basis"), (1, "hubble_client_tuple")):
            with self.subTest(marker=marker, basis=basis):
                edge = self._edge_rows(
                    self._run(
                        [
                            self._edge(client),
                            self._hconn(
                                client,
                                f"cid-{marker}",
                                pod,
                                basis=basis,
                                incomplete=marker,
                            ),
                        ]
                    )
                )[(client, self.frontend, 80, "tcp")]
                expected_coverage = "incomplete" if marker else "unresolved"
                self.assertEqual(edge["client_handoff_coverage"], expected_coverage)
                self.assertEqual(self._records(edge), [])

    def test_backend_scope_caps_and_missing_stage_metadata_fail_closed(self):
        client = "vm:scope-a/10.30.0.45"
        pod = "pod:handoff-cluster/pod-a"
        cases = {
            "backend cap": self._hconn(client, "backend-cap", pod, backend_capped=1),
            "scope cap": self._hconn(client, "scope-cap", pod, scope_capped=1),
            "missing stage marker": self._hconn(client, "no-marker", pod),
        }
        cases["missing stage marker"].pop("adm_v2_handoff_input_incomplete")
        for name, hconn in cases.items():
            with self.subTest(case=name):
                edge = self._edge_rows(self._run([self._edge(client), hconn]))[
                    (client, self.frontend, 80, "tcp")
                ]
                self.assertIn(
                    edge["client_handoff_coverage"], {"unresolved", "incomplete"}
                )
                self.assertEqual(self._records(edge), [])

    def test_partial_and_absent_hconn_are_distinguished_without_fabrication(self):
        client = "vm:scope-a/10.30.0.51"
        edge = self._edge(client)
        partial = self._edge_rows(
            self._run(
                [
                    edge,
                    self._hconn(client, "known", "pod:handoff-cluster/pod-a"),
                    self._hconn(client, "missing", None, basis=None),
                ]
            )
        )[(client, self.frontend, 80, "tcp")]
        absent = self._edge_rows(self._run([self._edge(client)]))[
            (client, self.frontend, 80, "tcp")
        ]
        self.assertEqual(partial["client_handoff_coverage"], "partial")
        self.assertEqual(
            (
                int(partial["client_handoff_connections"]),
                int(partial["client_handoff_determined"]),
                int(partial["client_handoff_unresolved"]),
            ),
            (2, 1, 1),
        )
        self.assertEqual(len(self._records(partial)), 1)
        self.assertEqual(absent["client_handoff_coverage"], "incomplete")
        self.assertEqual(self._records(absent), [])

    def test_more_than_64_targets_nodes_or_observers_marks_incomplete(self):
        client = "vm:scope-a/10.30.0.61"
        edge = self._edge(client)
        scenarios = {
            "groups": [
                self._hconn(client, f"g-{i}", f"pod:handoff-cluster/pod-{i}")
                for i in range(65)
            ],
            "nodes": [
                self._hconn(
                    client, f"n-{i}", "pod:handoff-cluster/shared", via=f"node-{i}"
                )
                for i in range(65)
            ],
            "observers": [
                self._hconn(
                    client, f"o-{i}", "pod:handoff-cluster/shared", observer=f"obs-{i}"
                )
                for i in range(65)
            ],
        }
        for name, hconns in scenarios.items():
            with self.subTest(cap=name):
                result = self._edge_rows(self._run([edge, *hconns]))[
                    (client, self.frontend, 80, "tcp")
                ]
                self.assertEqual(result["client_handoff_coverage"], "incomplete")
                self.assertEqual(self._records(result), [])

    def test_pre_handoff_input_stage_captures_capped_or_missing_connection_lists(self):
        payload_rows = [
            {
                "adm_row": "conv",
                "adm_keep": 1,
                "adm_s_kind": "k8s_service",
                "tag": "missing",
            },
            {
                "adm_row": "conv",
                "adm_keep": 1,
                "adm_s_kind": "k8s_service",
                "conns_capped": 1,
                "adm_conns": "51000@100@101",
                "tag": "capped",
            },
            {
                "adm_row": "conv",
                "adm_keep": 0,
                "adm_s_kind": "vm",
                "flow_source": "netflow",
                "tag": "unrelated",
            },
        ]

        def run_input_stage(values: list[dict]) -> list[dict]:
            payload = json.dumps(json.dumps(values, separators=(",", ":")))
            return lab.search(
                f"| makeresults format=json data={payload} "
                "| `adm_graph_client_handoff_inputs_v2` "
                "| table tag adm_v2_handoff_input_incomplete",
                "0",
                "+10y",
            )

        rows = run_input_stage(payload_rows)
        flags = {
            row["tag"]: int(row["adm_v2_handoff_input_incomplete"]) for row in rows
        }
        self.assertEqual(flags, {"missing": 1, "capped": 1, "unrelated": 1})
        unrelated = run_input_stage([payload_rows[-1]])
        self.assertEqual(len(unrelated), 1)
        self.assertEqual(int(unrelated[0]["adm_v2_handoff_input_incomplete"]), 0)


if __name__ == "__main__":
    unittest.main()
