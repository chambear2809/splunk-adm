"""Native evidence stays temporal and observer-qualified beside trace calls."""

import copy
import json
import unittest
from unittest.mock import patch

from tests.test_qualified_identity import PROFILE, interval_rows, span
from splunk_app.splunk_adm.bin.adm_identity_lib.network_graph import (
    assemble,
    configuration,
    owner_at,
    service_at,
)
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import EvidenceError, qualify
from splunk_app.splunk_adm.bin.adm_identity_lib.search import bounded_network_query

NETWORK = {
    "enabled": True,
    "profiles": [
        {
            "id": "sensor-a",
            "kind": "hubble",
            "index": "hubble",
            "source": "/hubble/",
            "sourcetype": "cilium:hubble:flow",
            "scope": "scope-a",
            "owner_scope": "scope-a",
            "cluster": "cluster-a",
            "observers": ["node-a"],
        }
    ],
    "frontends": [],
}
SELECTION = {
    "service": "checkout",
    "environment": "prod",
    "cluster": "cluster-a",
    "namespace": "shop",
}


def native(
    at=15,
    source="10.0.0.1",
    destination="203.0.113.9",
    cd="1:1",
    source_namespace="shop",
    source_port=1234,
    destination_port=443,
    verdict="FORWARDED",
    is_reply=False,
    traffic_direction="EGRESS",
):
    import datetime

    stamp = (
        datetime.datetime.fromtimestamp(at, datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    flow = {
        "time": stamp,
        "node_name": "node-a",
        "Type": "L3_L4",
        "verdict": verdict,
        "is_reply": is_reply,
        "trace_observation_point": "TO_STACK",
        "traffic_direction": traffic_direction,
        "IP": {"source": source, "destination": destination},
        "l4": {
            "TCP": {"source_port": source_port, "destination_port": destination_port}
        },
        "source": {"namespace": source_namespace, "pod_name": "checkout-a"},
    }
    return {
        "_raw": json.dumps({"flow": flow, "time": stamp, "node_name": "node-a"}),
        "index": "hubble",
        "source": "/hubble/",
        "sourcetype": "cilium:hubble:flow",
        "event_time": str(at),
        "receipt_time": str(at + 1),
        "host": "node-a",
        "k8s.cluster.name": "cluster-a",
        "_bkt": "hubble~1~a",
        "_cd": cd,
    }


class QualifiedNetworkTests(unittest.TestCase):
    def result(self, rows=None):
        value = qualify(rows or interval_rows() + [span()], PROFILE, 0, 100)
        self.assertTrue(value["complete"], value)
        return value

    def test_native_point_owner_and_service_membership_have_distinct_clocks(self):
        result = self.result()
        owner, status = owner_at(result, "10.0.0.1", 15, 15, "scope-a")
        self.assertEqual(status, "qualified")
        self.assertEqual(
            service_at(result, owner, "10.0.0.1", 15, 15)[0], "concurrent_span"
        )
        self.assertEqual(
            service_at(result, owner, "10.0.0.1", 25, 25)[0], "workload_only"
        )
        self.assertIsNone(owner_at(result, "10.0.0.1", 30, 30, "scope-a")[0])
        self.assertIsNone(owner_at(result, "10.0.0.1", 15, 15, "another-scope")[0])

    def test_invalidation_at_exact_point_start_blocks_ownership(self):
        result = self.result()
        result["ownership_invalidations"] = [
            {"ip": "10.0.0.1", "valid_from": 15, "valid_to": 17}
        ]
        self.assertIsNone(owner_at(result, "10.0.0.1", 15, 15, "scope-a")[0])
        self.assertIsNotNone(owner_at(result, "10.0.0.1", 17, 17, "scope-a")[0])

    def test_overlapping_owner_reassignment_never_picks_a_uid(self):
        result = self.result()
        competitor = dict(result["owner_records"][0], pod_uid="another-uid")
        result["owner_records"].append(competitor)
        self.assertEqual(
            owner_at(result, "10.0.0.1", 15, 15, "scope-a")[1], "ambiguous_ownership"
        )

    def test_observations_do_not_create_calls_conversations_or_translations(self):
        rows = assemble(
            self.result(), [native()], configuration(NETWORK, PROFILE), SELECTION
        )
        obs = [r for r in rows if r.get("relationship") == "traffic_observation"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["count"], 1)
        self.assertEqual(obs[0]["source_ip"], "10.0.0.1")
        self.assertEqual(obs[0]["destination_ip"], "203.0.113.9")
        self.assertNotIn("bytes", obs[0])
        self.assertNotIn("server_port", obs[0])
        self.assertFalse(
            any(
                r.get("relationship") in ["communicates_with", "forwards_to"]
                for r in rows
            )
        )
        body = json.loads(obs[0]["traffic_observations"])[0]
        self.assertFalse(body["is_reply"])
        self.assertFalse(body["metrics_authoritative"])
        self.assertNotIn("raw_bytes", body)
        self.assertEqual(body["observation_point"], "node-a/TO_STACK")
        self.assertTrue(
            any("Source ownership: qualified" in item for item in obs[0]["evidence"])
        )
        self.assertTrue(
            any(
                "destination ownership: ownership_not_covered" in item
                for item in obs[0]["evidence"]
            )
        )
        self.assertTrue(
            any(
                "Source service at observation time: concurrent_span" in item
                for item in obs[0]["evidence"]
            )
        )
        self.assertTrue(
            any(
                "destination service at observation time: not_pod_attributed" in item
                for item in obs[0]["evidence"]
            )
        )
        self.assertEqual(
            next(r for r in rows if r["row_type"] == "meta")["network_records"], 1
        )

    def test_sensor_namespace_cannot_override_the_finite_owner(self):
        rows = assemble(
            self.result(),
            [native(source_namespace="other")],
            configuration(NETWORK, PROFILE),
            SELECTION,
        )
        self.assertFalse(
            any(r.get("relationship") == "traffic_observation" for r in rows)
        )

    def test_record_chunking_retains_all_fingerprints_and_does_not_count_connections(
        self,
    ):
        events = [native(cd=f"1:{i}") for i in range(130)]
        rows = assemble(
            self.result(), events, configuration(NETWORK, PROFILE), SELECTION
        )
        edges = [r for r in rows if r.get("relationship") == "traffic_observation"]
        self.assertEqual([r["records"] for r in edges], [64, 64, 2])
        self.assertEqual(sum(r["count"] for r in edges), 130)
        fingerprints = [
            o["record_fingerprint"]
            for e in edges
            for o in json.loads(e["traffic_observations"])
        ]
        self.assertEqual(len(set(fingerprints)), 130)

    def test_ephemeral_port_cardinality_is_bounded_without_collapsing_tuples(self):
        events = [
            native(
                cd=f"ports:{i}",
                source_port=10000 + i,
                destination_port=40000 + (i % 1000),
            )
            for i in range(2001)
        ]
        rows = assemble(
            self.result(), events, configuration(NETWORK, PROFILE), SELECTION
        )
        edges = [r for r in rows if r.get("relationship") == "traffic_observation"]
        self.assertEqual(sum(r["count"] for r in edges), 2001)
        self.assertEqual(len(edges), 32)
        fingerprints = {
            observation["record_fingerprint"]
            for edge in edges
            for observation in json.loads(edge["traffic_observations"])
        }
        self.assertEqual(len(fingerprints), 2001)
        meta = next(r for r in rows if r["row_type"] == "meta")
        self.assertEqual(meta["network_edge_budget_omitted"], 0)
        self.assertGreater(meta["network_edge_budget_remaining"], 0)

    def test_direction_and_verdict_variants_remain_separate_observation_edges(self):
        rows = assemble(
            self.result(),
            [
                native(cd="variant:forward", verdict="FORWARDED", is_reply=False),
                native(cd="variant:reply", verdict="DROPPED", is_reply=True),
            ],
            configuration(NETWORK, PROFILE),
            SELECTION,
        )
        edges = [r for r in rows if r.get("relationship") == "traffic_observation"]
        self.assertEqual(len(edges), 2)
        variants = {
            (payload["verdict"], payload["is_reply"])
            for edge in edges
            for payload in json.loads(edge["traffic_observations"])
        }
        self.assertEqual(variants, {("FORWARDED", False), ("DROPPED", True)})

    def test_edge_budget_omissions_are_explicit_and_truthful(self):
        events = [
            native(cd=f"direction:{i}", traffic_direction=f"D-{i}") for i in range(2001)
        ]
        rows = assemble(
            self.result(), events, configuration(NETWORK, PROFILE), SELECTION
        )
        meta = next(r for r in rows if r["row_type"] == "meta")
        self.assertEqual(meta["edges"], 2000)
        # One record is rejected at MAX_GROUPS and one more cannot be rendered
        # after the OTel membership edge consumes one slot.
        self.assertEqual(meta["network_edge_budget_omitted"], 2)
        self.assertEqual(meta["network_records"], 1999)
        self.assertTrue(any("Partial native graph" in w for w in meta["warnings"]))
        self.assertIn(
            "edge_budget=2", next(w for w in meta["warnings"] if "not included" in w)
        )

    def test_observation_budget_omissions_are_counted_once(self):
        events = [native(cd=f"observation:{i}") for i in range(5)]
        with patch(
            "splunk_app.splunk_adm.bin.adm_identity_lib.network_graph.MAX_STORED_OBSERVATIONS",
            3,
        ):
            rows = assemble(
                self.result(), events, configuration(NETWORK, PROFILE), SELECTION
            )
        meta = next(r for r in rows if r["row_type"] == "meta")
        self.assertEqual(meta["network_records"], 3)
        self.assertEqual(meta["network_observation_budget_omitted"], 2)
        self.assertTrue(any("Partial native graph" in w for w in meta["warnings"]))

    def test_budget_admission_is_stable_when_input_order_changes(self):
        events = [
            native(cd=f"direction:{i}", traffic_direction=f"D-{i}") for i in range(4)
        ]
        first = assemble(
            self.result(), events, configuration(NETWORK, PROFILE), SELECTION
        )
        with patch(
            "splunk_app.splunk_adm.bin.adm_identity_lib.network_graph.MAX_GROUPS", 1
        ):
            ordered = assemble(
                self.result(), events, configuration(NETWORK, PROFILE), SELECTION
            )
            reversed_rows = assemble(
                self.result(),
                list(reversed(events)),
                configuration(NETWORK, PROFILE),
                SELECTION,
            )

        def signature(rows):
            meta = next(r for r in rows if r["row_type"] == "meta")
            observations = sorted(
                o["record_fingerprint"]
                for edge in rows
                if edge.get("relationship") == "traffic_observation"
                for o in json.loads(edge["traffic_observations"])
            )
            return (
                meta["network_records"],
                meta["network_edge_budget_omitted"],
                observations,
            )

        self.assertNotEqual(signature(first), signature(ordered))
        self.assertEqual(signature(ordered), signature(reversed_rows))

    def test_concurrent_distinct_service_set_not_overlapping_span_count(self):
        result = self.result()
        owner = result["owner_records"][0]
        result["bindings"].append(dict(result["bindings"][0], span_id="c" * 16))
        self.assertEqual(
            service_at(result, owner, "10.0.0.1", 15, 15)[0], "concurrent_span"
        )
        result["bindings"].append(dict(result["bindings"][0], service="other"))
        self.assertEqual(
            service_at(result, owner, "10.0.0.1", 15, 15)[0], "ambiguous_service"
        )

    def test_query_reads_full_source_families_without_address_pushdown(self):
        query = bounded_network_query(NETWORK["profiles"], PROFILE, 0, 100)
        self.assertIn('source="/hubble/"', query)
        self.assertIn("_bkt _cd", query)
        self.assertIn("head 50001", query)
        self.assertNotIn("src_ip=", query)
        self.assertNotIn("IPv6", query)

    def test_frontend_intent_keeps_exporter_observations_separate_from_pods(self):
        config = copy.deepcopy(NETWORK)
        config["profiles"] = [
            {
                "id": "exporter-a",
                "kind": "netflow",
                "index": "flows",
                "source": "stream:netflow",
                "sourcetype": "stream:netflow",
                "scope": "routing-a",
                "cluster": "cluster-a",
                "exporter_ip": "192.0.2.30",
                "netflow_version": 10,
                "observation_domain_present": True,
                "observation_domain_id": 0,
            }
        ]
        config["frontends"] = [
            {
                **SELECTION,
                "scope": "routing-a",
                "address": "192.0.2.20",
                "valid_from": 10,
                "valid_to": 30,
            }
        ]
        raw = {
            "exporter_ip": "192.0.2.30",
            "netflow_version": 10,
            "observation_domain_id": 0,
            "timestamp": "1970-01-01T00:00:14Z",
            "endtime": "1970-01-01T00:00:15Z",
            "src_ip": "192.0.2.10",
            "dest_ip": "192.0.2.20",
            "src_port": 1234,
            "dest_port": 8080,
            "protoid": 6,
            "bytes_in": 200,
            "packets_in": 4,
            "flow_dir": 0,
        }
        event = {
            "_raw": json.dumps(raw),
            "index": "flows",
            "source": "stream:netflow",
            "sourcetype": "stream:netflow",
            "event_time": "15",
            "receipt_time": "16",
            "_bkt": "flows~1~a",
            "_cd": "1:1",
        }
        rows = assemble(
            self.result(), [event], configuration(config, PROFILE), SELECTION
        )
        edge = next(r for r in rows if r.get("relationship") == "traffic_observation")
        self.assertEqual(edge["sources"], ["netflow"])
        self.assertNotIn("server_port", edge)
        self.assertNotIn("bytes", edge)
        observation = json.loads(edge["traffic_observations"])[0]
        self.assertEqual(observation["raw_bytes"], 200)
        self.assertEqual(observation["direction"], "0")
        self.assertEqual(observation["netflow_version"], 10)
        self.assertEqual(observation["observation_domain_present"], 1)
        self.assertFalse(observation["metrics_authoritative"])
        self.assertTrue(any(r.get("endpoint_kind") == "k8s_service" for r in rows))
        self.assertFalse(any(r.get("relationship") == "forwards_to" for r in rows))
        late = dict(event, receipt_time="100")
        rows = assemble(
            self.result(), [late], configuration(config, PROFILE), SELECTION
        )
        self.assertFalse(
            any(r.get("relationship") == "traffic_observation" for r in rows)
        )

    def test_unbounded_or_cross_scope_frontend_intent_is_not_accepted(self):
        config = copy.deepcopy(NETWORK)
        config["frontends"] = [
            {
                **SELECTION,
                "address": "192.0.2.1",
                "scope": "scope-a",
                "valid_from": 0,
                "valid_to": 100000,
            }
        ]
        with self.assertRaises(EvidenceError):
            configuration(config, PROFILE)

    def test_frontend_history_accepts_only_disjoint_finite_windows(self):
        config = copy.deepcopy(NETWORK)
        config["profiles"] = [
            {
                "id": "exporter-a",
                "kind": "netflow",
                "index": "flows",
                "source": "stream:netflow",
                "sourcetype": "stream:netflow",
                "scope": "routing-a",
                "cluster": "cluster-a",
                "exporter_ip": "192.0.2.30",
                "netflow_version": 10,
                "observation_domain_present": True,
                "observation_domain_id": 0,
            }
        ]
        first = {
            **SELECTION,
            "address": "192.0.2.20",
            "scope": "routing-a",
            "valid_from": 10,
            "valid_to": 30,
        }
        config["frontends"] = [first, {**first, "valid_from": 30, "valid_to": 50}]
        self.assertEqual(len(configuration(config, PROFILE)["frontends"]), 2)
        for start, end in [(29, 50), (10, 30), (5, 11), (15, 20)]:
            with self.subTest(start=start, end=end):
                config["frontends"] = [
                    first,
                    {**first, "valid_from": start, "valid_to": end},
                ]
                with self.assertRaises(EvidenceError):
                    configuration(config, PROFILE)


if __name__ == "__main__":
    unittest.main()
