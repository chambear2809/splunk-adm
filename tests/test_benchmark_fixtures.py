"""Independent invariants for the TA-shaped scale workload."""

import ipaddress
import json
import unittest
from collections import Counter

from tools.benchmark_fixtures import BASE, Workload, iter_events, manifest


class BenchmarkFixturesTest(unittest.TestCase):
    def test_determinism_and_manifest_counts(self):
        config = Workload(3, 4, 2, 3, 2)
        events = list(iter_events(config))
        self.assertEqual(events, list(iter_events(config)))
        expected = manifest(config)["expected"]
        self.assertEqual(len(events), 7 + 24 + 9)
        counts = Counter(e["sourcetype"] for e in events)
        self.assertEqual(counts["kube:object:pods"], 7)
        self.assertEqual(counts["stream:netflow"], 24)
        self.assertEqual(counts["otel:traces"], 9)
        self.assertEqual(expected["events"], len(events))
        self.assertEqual(expected["flow_bytes"], 7200)
        self.assertEqual(expected["graph_bytes"], 3600)
        self.assertEqual(expected["identity_rows"], 8)
        self.assertEqual(expected["bindings"], 4)
        json.dumps(events)

    def test_ip_scaling_and_history_are_consistent(self):
        events = [
            e
            for e in iter_events(Workload(400, 1, 3))
            if e["sourcetype"] == "kube:object:pods"
        ]
        uids = set()
        histories = {}
        for event in events:
            obj = event["event"]["object"]
            ipaddress.ip_address(obj["status"]["podIP"])
            self.assertEqual(obj["status"]["podIPs"][0]["ip"], obj["status"]["podIP"])
            self.assertEqual(obj["metadata"]["uid"], event["fields"]["k8s.pod.uid"])
            self.assertEqual(
                obj["metadata"]["creationTimestamp"], obj["status"]["startTime"]
            )
            self.assertNotIn(obj["metadata"]["uid"], uids)
            uids.add(obj["metadata"]["uid"])
            histories.setdefault(obj["status"]["podIP"], []).append(event["time"])
        self.assertEqual(len(histories), 401)
        self.assertEqual(len(uids), 1201)
        for times in histories.values():
            self.assertEqual(times, sorted(set(times)))
            self.assertLess(max(times), BASE - 300)

    def test_trace_references_and_scope_mapping(self):
        config = Workload(5, 2, 3, 5)
        events = list(iter_events(config))
        pods = {
            e["event"]["object"]["metadata"]["uid"]
            for e in events
            if e["sourcetype"] == "kube:object:pods"
        }
        traces = [e for e in events if e["sourcetype"] == "otel:traces"]
        ids = {(e["event"]["trace_id"], e["event"]["span_id"]) for e in traces}
        self.assertEqual(len(ids), 15)
        args = manifest(config)["graph_args"]
        for e in traces:
            self.assertIn(e["fields"]["k8s.pod.uid"], pods)
            self.assertEqual(e["fields"]["k8s.cluster.name"], args["cluster"])
            self.assertEqual(e["fields"]["k8s.namespace.name"], args["namespace"])
            if e["event"]["parent_span_id"]:
                self.assertIn(
                    (e["event"]["trace_id"], e["event"]["parent_span_id"]), ids
                )
        scope = manifest(config)["scope_rows"]
        self.assertEqual({r["observer_kind"] for r in scope}, {"exporter", "cluster"})
        self.assertEqual(len({r["scope"] for r in scope}), 1)

    def test_shared_observers_preserve_traffic_and_vary_physical_records(self):
        one = Workload(5, 2, 1, 5, 1)
        three = Workload(5, 2, 1, 5, 3)
        self.assertEqual(
            manifest(one)["expected"]["graph_bytes"],
            manifest(three)["expected"]["graph_bytes"],
        )
        self.assertEqual(
            3 * manifest(one)["expected"]["flows"], manifest(three)["expected"]["flows"]
        )
        flows = [
            e["event"]
            for e in iter_events(three)
            if e["sourcetype"] == "stream:netflow"
        ]
        self.assertEqual(len({f["seqnumber"] for f in flows}), len(flows))
        per_pair = {}
        for f in flows:
            per_pair.setdefault(f["dest_ip"], set()).add(f["exporter_ip"])
        self.assertTrue(all(len(observers) == 3 for observers in per_pair.values()))
        self.assertEqual(len({f["exporter_ip"] for f in flows}), 5)

    def test_connection_cardinality_is_independent_of_record_volume(self):
        config = Workload(3, 100, exporters=3, connections_per_pair=50)
        flows = [
            e["event"]
            for e in iter_events(config)
            if e["sourcetype"] == "stream:netflow"
        ]
        self.assertEqual(len(flows), 300)
        self.assertEqual(len({(f["dest_ip"], f["src_port"]) for f in flows}), 150)
        self.assertEqual(manifest(config)["expected"]["graph_connections"], 150)
        with self.assertRaises(ValueError):
            Workload(flow_copies=10, connections_per_pair=11)

    def test_input_limits_and_combined_budget(self):
        for kwargs in (
            {"pods": 0},
            {"pods": True},
            {"history": 0},
            {"exporters": 129},
            {"observer_copies": 2},
            {"pods": 10000, "flow_copies": 10000},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Workload(**kwargs)


if __name__ == "__main__":
    unittest.main()
