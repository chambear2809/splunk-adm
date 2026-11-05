"""Qualified summaries reproduce the per-slice qualified graph with exact totals."""

import copy
import datetime
import hashlib
import json
import unittest
from collections import defaultdict

from splunk_app.splunk_adm.bin.adm_identity_lib import rollup
from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import normalize_records
from splunk_app.splunk_adm.bin.adm_identity_lib.network_graph import (
    assemble,
    configuration,
)
from splunk_app.splunk_adm.bin.adm_identity_lib.protocol import canonical, owners_digest
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import qualify, service_id
from splunk_app.splunk_adm.bin.adm_identity_lib.slices import merge
from tests.test_qualified_identity import PROFILE

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
            "observers": ["node-a", "node-b"],
        },
        {
            "id": "vds",
            "kind": "netflow",
            "index": "netflow",
            "source": "stream:netflow",
            "sourcetype": "stream:netflow",
            "scope": "fabric",
            "cluster": "cluster-a",
            "exporter_ip": "192.0.2.13",
            "netflow_version": 10,
            "observation_domain_present": True,
            "observation_domain_id": 0,
        },
    ],
    "frontends": [
        {
            "address": "198.51.100.7",
            "scope": "fabric",
            "service": "checkout",
            "environment": "prod",
            "cluster": "cluster-a",
            "namespace": "shop",
            "valid_from": 0,
            "valid_to": 1200,
        }
    ],
}
CHECKOUT = {
    "service": "checkout",
    "environment": "prod",
    "cluster": "cluster-a",
    "namespace": "shop",
}
UNRELATED = dict(CHECKOUT, service="search")


def stamp(at):
    return (
        datetime.datetime.fromtimestamp(at, datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def interval(row_receipt, observed, start, end, snapshot, owners):
    shared = {
        "schema": "adm:pod_ip_interval:v2",
        "cluster": "cluster-a",
        "environment": "prod",
        "producer_id": "producer-a",
        "producer_epoch": "epoch-a",
        "valid_from": start,
        "valid_to": end,
        "observed_at": observed,
        "snapshot_id": snapshot,
    }
    records = []
    for uid, address in owners:
        owner = {
            **shared,
            "kind": "owner",
            "namespace": "shop",
            "pod_uid": uid,
            "ip": address,
            "host_network": False,
            "node_name": "node-a",
            "operation": "present",
        }
        owner["record_id"] = hashlib.sha256(canonical(owner).encode()).hexdigest()
        records.append(owner)
    manifest = {
        **shared,
        "kind": "manifest",
        "checkpoint_nonce": "nonce-" + snapshot,
        "namespace_scope": "all",
        "expected_count": len(records),
        "owners_sha256": owners_digest(records),
        "invalidated_ips": [],
    }
    return [
        {
            "index": "identity",
            "source": "producer-a",
            "sourcetype": "adm:pod_ip_interval:v2",
            "event_time": observed,
            "receipt_time": row_receipt,
            "_raw": json.dumps(value),
        }
        for value in [*records, manifest]
    ]


def span(service, sid, uid, start, end, trace="a", kind="SERVER", parent=None):
    raw = {
        "trace_id": trace * 32,
        "span_id": sid * 16,
        "kind": "SPAN_KIND_" + kind,
        "start_time": int(start * 1e9),
        "end_time": int(end * 1e9),
        "service.name": service,
        "deployment.environment.name": "prod",
        "k8s.cluster.name": "cluster-a",
        "k8s.namespace.name": "shop",
        "k8s.pod.uid": uid,
    }
    if parent:
        raw["parent_span_id"] = parent * 16
    return {
        "index": "traces",
        "source": "otel-a",
        "sourcetype": "otel:traces",
        "event_time": start,
        "receipt_time": end + 1,
        "_raw": json.dumps(raw),
    }


def hubble(at, cd, source, destination, receipt=None, pod="checkout-1", node="node-a"):
    flow = {
        "time": stamp(at),
        "node_name": node,
        "Type": "L3_L4",
        "verdict": "DROPPED" if cd.endswith("d") else "FORWARDED",
        "is_reply": False,
        "trace_observation_point": "TO_STACK",
        "traffic_direction": "EGRESS",
        "IP": {"source": source, "destination": destination},
        "l4": {
            "TCP": {"source_port": 40000 + int(at) % 20000, "destination_port": 8080}
        },
        "source": {"namespace": "shop", "pod_name": pod},
    }
    return {
        "_raw": json.dumps({"flow": flow, "time": stamp(at), "node_name": node}),
        "index": "hubble",
        "source": "/hubble/",
        "sourcetype": "cilium:hubble:flow",
        "event_time": str(at),
        "receipt_time": str(receipt if receipt is not None else at + 1),
        "host": node,
        "k8s.cluster.name": "cluster-a",
        "_bkt": "hubble~1~a",
        "_cd": cd,
    }


def netflow(at, cd, source, destination, octets):
    raw = {
        "exporter_ip": "192.0.2.13",
        "netflow_version": 10,
        "observation_domain_id": 0,
        "src_ip": source,
        "dest_ip": destination,
        "timestamp": stamp(at - 1),
        "endtime": stamp(at),
        "protoid": 6,
        "src_port": 51000,
        "dest_port": 443,
        "bytes_in": octets,
        "packets_in": 3,
    }
    return {
        "_raw": json.dumps(raw),
        "index": "netflow",
        "source": "stream:netflow",
        "sourcetype": "stream:netflow",
        "event_time": str(at),
        "receipt_time": str(at + 2),
        "_bkt": "netflow~1~a",
        "_cd": cd,
    }


def scenario(base=0):
    """Two slices; payments is rescheduled mid-second-slice (same IP, new UID).

    ``base`` shifts every clock (the Splunk lab rebases into the recent past).
    """
    b = base
    identity = {
        b: interval(
            b + 296,
            b + 295,
            b + 10,
            b + 290,
            "s0",
            [("uid-a", "10.0.0.1"), ("uid-b", "10.0.0.2"), ("uid-s", "10.0.0.5")],
        )
        + [
            span("checkout", "1", "uid-a", b + 20, b + 30, kind="CLIENT"),
            span("payments", "2", "uid-b", b + 21, b + 29, parent="1"),
            span("search", "3", "uid-s", b + 22, b + 28, trace="b"),
        ],
        b + 300: interval(
            b + 446,
            b + 445,
            b + 310,
            b + 440,
            "s1",
            [("uid-a", "10.0.0.1"), ("uid-b", "10.0.0.2")],
        )
        + interval(
            b + 596,
            b + 595,
            b + 450,
            b + 590,
            "s2",
            [("uid-a", "10.0.0.1"), ("uid-c", "10.0.0.2")],
        )
        + [
            span("checkout", "4", "uid-a", b + 320, b + 330, trace="c", kind="CLIENT"),
            span("payments", "5", "uid-b", b + 321, b + 329, trace="c", parent="4"),
            span("checkout", "6", "uid-a", b + 460, b + 470, trace="d", kind="CLIENT"),
            span("payments", "7", "uid-c", b + 461, b + 469, trace="d", parent="6"),
        ],
    }
    native = {
        b: [hubble(b + t, f"0:{t}", "10.0.0.1", "10.0.0.2") for t in range(40, 280, 20)]
        + [hubble(b + 250, "0:250d", "10.0.0.1", "10.0.0.2")]
        + [hubble(b + 60, "0:x", "10.0.0.9", "10.0.0.8", pod="other")]
        # Indexed after the slice ended but within accepted lateness.
        + [hubble(b + 285, "0:late", "10.0.0.1", "203.0.113.9", receipt=b + 330)]
        + [netflow(b + 100, "0:n1", "198.51.100.7", "203.0.113.20", 1500)],
        b + 300: [
            hubble(b + t, f"1:{t}", "10.0.0.1", "10.0.0.2") for t in (320, 400, 430)
        ]
        + [hubble(b + t, f"2:{t}", "10.0.0.1", "10.0.0.2") for t in (460, 500, 580)]
        + [netflow(b + 400, "1:n1", "198.51.100.7", "203.0.113.20", 500)],
    }
    return identity, native


def frontends(base=0):
    return [
        dict(f, valid_from=f["valid_from"] + base, valid_to=f["valid_to"] + base)
        for f in NETWORK["frontends"]
    ]


def config():
    return configuration(copy.deepcopy(NETWORK), PROFILE)


def raw_graph(identity, native, selection, windows, start, end):
    outputs, read = [], []
    for a, b in windows:
        result = qualify(identity[a], PROFILE, a, b)
        assert result["complete"], result
        try:
            outputs.append(assemble(result, native[a], config(), selection))
        except ValueError as exc:
            if "no qualified observations" not in str(exc):
                raise
        read.append((a, b))
    return merge(outputs, start, end, len(windows), read)


def summary_docs(identity, native, windows, lateness=0, fp=None):
    network = config()
    fp = fp or rollup.fingerprint(PROFILE, network)
    docs = []
    for a, b in windows:
        horizon = b + lateness
        result = qualify(identity[a], PROFILE, a, b, horizon)
        assert result["complete"], result
        decoded = normalize_records(
            native[a], network["profiles"], a, b, horizon=horizon
        )
        docs.extend(rollup.summarize(result, decoded, network, a, b, horizon, fp))
    return docs


def manifests(docs, root):
    """Reference implementation of manifest_query over documents."""
    groups = defaultdict(list)
    for doc in docs:
        groups[(doc["q_slice"], doc["q_run"])].append(doc)
    rows = []
    for (slice_start, run), values in groups.items():
        manifest = next((d for d in values if d["q_kind"] == "m"), {})
        rows.append(
            {
                "q_slice": slice_start,
                "q_run": run,
                "rows": len(values),
                "docs": len({d["q_doc"] for d in values}),
                "root": int(
                    any(d["q_kind"] == "s" and d["q_key"] == root for d in values)
                ),
                "expected": manifest.get("q_expected"),
                "horizon": manifest.get("q_horizon"),
                "status": manifest.get("q_status"),
                "meta": manifest.get("q_meta"),
            }
        )
    return rows


def summary_graph(docs, selection, start, end, windows):
    root_sid = service_id(selection)
    root = rollup.root_token(root_sid)
    chosen, excluded, duplicated = rollup.choose_runs(manifests(docs, root), start, end)
    runs = {c["run"] for c in chosen.values()}
    rows = rollup.aggregate(docs, root, runs)
    output = rollup.render(
        rows, selection, root_sid, chosen, "scope-a", "cluster-a", True
    )
    return merge([output] if output else [], start, end, len(windows), windows), (
        chosen,
        excluded,
        duplicated,
    )


def edges_by(graph, relationship):
    return {
        e["id"]: e
        for e in graph
        if e.get("row_type") == "edge" and e.get("relationship") == relationship
    }


WINDOWS = [(0, 300), (300, 600)]


class SummaryEquivalenceTests(unittest.TestCase):
    def test_summary_graph_equals_union_of_per_slice_qualified_graphs(self):
        identity, native = scenario()
        docs = summary_docs(identity, native, WINDOWS)
        for selection in (CHECKOUT, UNRELATED, dict(CHECKOUT, service="payments")):
            with self.subTest(selection["service"]):
                self.assert_equivalent(
                    raw_graph(identity, native, selection, WINDOWS, 0, 600),
                    summary_graph(docs, selection, 0, 600, WINDOWS)[0],
                )
        frontend = [
            n
            for n in summary_graph(docs, CHECKOUT, 0, 600, WINDOWS)[0]
            if n.get("endpoint_kind") == "k8s_service"
        ]
        self.assertEqual([n["addresses"] for n in frontend], [["198.51.100.7"]])

    def assert_equivalent(self, raw, summary):
        self.assertEqual(
            {n["id"] for n in raw if n["row_type"] == "node"},
            {n["id"] for n in summary if n["row_type"] == "node"},
        )
        for relationship in ("calls", "runs_on", "traffic_observation"):
            raw_edges = edges_by(raw, relationship)
            summary_edges = edges_by(summary, relationship)
            self.assertEqual(set(raw_edges), set(summary_edges), relationship)
            for ident, edge in raw_edges.items():
                other = summary_edges[ident]
                for field in (
                    "count",
                    "records",
                    "raw_bytes",
                    "raw_packets",
                    "blocked_records",
                    "first_seen",
                    "last_seen",
                    "source",
                    "target",
                    "destination_port",
                ):
                    self.assertEqual(edge.get(field), other.get(field), field)
        self.assertEqual(raw[-1]["network_records"], summary[-1]["network_records"])
        self.assertEqual(raw[-1]["spans"], summary[-1]["spans"])
        labels = {
            n["id"]: n["label"]
            for n in summary
            if n["row_type"] == "node" and n["kind"] == "workload"
        }
        self.assertEqual(
            labels, {n["id"]: n["label"] for n in raw if n.get("kind") == "workload"}
        )

    def test_totals_are_exact_across_slice_boundaries(self):
        identity, native = scenario()
        summary, _ = summary_graph(
            summary_docs(identity, native, WINDOWS), CHECKOUT, 0, 600, WINDOWS
        )
        traffic = edges_by(summary, "traffic_observation").values()
        # 12 + 1 dropped in slice 0, 3 + 3 in slice 1, two NetFlow intent records.
        self.assertEqual(sum(e["records"] for e in traffic), 21)
        netflow = [e for e in traffic if e["sources"] == ["netflow"]]
        self.assertEqual(
            [(e["records"], e["raw_bytes"], e["raw_packets"]) for e in netflow],
            [(2, 2000, 6)],
        )
        self.assertEqual(sum(e.get("blocked_records", 0) for e in traffic), 1)

    def test_reschedule_mid_slice_keeps_uids_apart(self):
        identity, native = scenario()
        summary, _ = summary_graph(
            summary_docs(identity, native, WINDOWS), CHECKOUT, 0, 600, WINDOWS
        )
        pods = {
            n["attr_pod_uid"]: n
            for n in summary
            if n["row_type"] == "node" and n["kind"] == "workload"
        }
        self.assertEqual(set(pods), {"uid-a", "uid-b", "uid-c"})
        to_pod = defaultdict(int)
        for edge in edges_by(summary, "traffic_observation").values():
            if edge["target"].startswith("pod:"):
                to_pod[edge["target"].rsplit("/", 1)[1]] += edge["records"]
        # 13 in slice 0 and 3 before the reschedule go to uid-b; 3 to uid-c.
        self.assertEqual(dict(to_pod), {"uid-b": 16, "uid-c": 3})
        runs_on = {
            (e["source"].split("/")[2], e["target"].rsplit("/", 1)[1]): e["count"]
            for e in edges_by(summary, "runs_on").values()
        }
        self.assertEqual(
            runs_on,
            {
                ("checkout", "uid-a"): 3,
                ("payments", "uid-b"): 2,
                ("payments", "uid-c"): 1,
            },
        )

    def test_selection_relevance_is_per_component(self):
        identity, native = scenario()
        docs = summary_docs(identity, native, WINDOWS)
        summary, (chosen, _, _) = summary_graph(docs, UNRELATED, 0, 600, WINDOWS)
        self.assertEqual(
            [n["id"] for n in summary if n["row_type"] == "node"],
            [service_id(UNRELATED)],
        )
        self.assertEqual(summary[-1]["network_records"], 0)
        self.assertEqual(len(chosen), 2)

    def test_late_events_need_accepted_lateness(self):
        identity, native = scenario()
        prompt, _ = summary_graph(
            summary_docs(identity, native, WINDOWS), CHECKOUT, 0, 600, WINDOWS
        )
        late, _ = summary_graph(
            summary_docs(identity, native, WINDOWS, lateness=60),
            CHECKOUT,
            0,
            600,
            WINDOWS,
        )
        self.assertEqual(late[-1]["network_records"], prompt[-1]["network_records"] + 1)

    def test_replays_are_idempotent_and_superseded_runs_are_ignored(self):
        identity, native = scenario()
        docs = summary_docs(identity, native, WINDOWS)
        again = summary_docs(identity, native, WINDOWS)
        self.assertEqual(docs, again)  # deterministic run and document IDs
        expected, _ = summary_graph(docs, CHECKOUT, 0, 600, WINDOWS)
        replayed, (_, excluded, duplicated) = summary_graph(
            docs + again, CHECKOUT, 0, 600, WINDOWS
        )
        self.assertEqual(len(duplicated), 2)
        self.assertEqual(excluded, [])
        self.assertEqual(
            replayed[-1]["network_records"], expected[-1]["network_records"]
        )
        later = summary_docs(identity, native, WINDOWS, lateness=60)
        mixed, (chosen, excluded, _) = summary_graph(
            docs + later, CHECKOUT, 0, 600, WINDOWS
        )
        self.assertEqual(len(excluded), 2)
        self.assertTrue(all(c["horizon"] == c["slice"] + 360 for c in chosen.values()))
        self.assertEqual(
            mixed[-1]["network_records"], expected[-1]["network_records"] + 1
        )

    def test_incomplete_runs_and_changed_configuration_are_not_read(self):
        identity, native = scenario()
        docs = summary_docs(identity, native, WINDOWS)
        partial = [d for d in docs if not (d["q_slice"] == 300 and d["q_kind"] == "f")]
        _, (chosen, excluded, _) = summary_graph(partial, CHECKOUT, 0, 600, WINDOWS)
        self.assertEqual(sorted(chosen), [0])
        self.assertEqual(len(excluded), 1)
        changed = copy.deepcopy(NETWORK)
        changed["frontends"][0]["valid_to"] = 900
        self.assertNotEqual(
            rollup.fingerprint(PROFILE, configuration(changed, PROFILE)),
            rollup.fingerprint(PROFILE, config()),
        )

    def test_empty_slices_are_covered_without_contributing(self):
        docs = rollup.summarize(None, None, None, 0, 300, 300, "a" * 24, "empty")
        self.assertEqual([d["q_kind"] for d in docs], ["m"])
        chosen, _, _ = rollup.choose_runs(manifests(docs, "r" + "0" * 16), 0, 300)
        self.assertEqual(chosen[0]["meta"]["status"], "empty")
        self.assertIsNone(
            rollup.render([], CHECKOUT, service_id(CHECKOUT), chosen, "s", "c", True)
        )


class SummaryQueryTests(unittest.TestCase):
    def test_queries_are_bounded_and_reject_injection(self):
        root = rollup.root_token(service_id(CHECKOUT))
        query = rollup.aggregate_query(
            "adm_summary_v2", "a" * 24, 0, 600, root, ["b" * 24]
        )
        self.assertIn(f"TERM({root})", query)
        self.assertIn("NOT q_run IN (" + "b" * 24 + ")", query)
        self.assertNotIn("dedup", query)
        self.assertIn(
            "dedup q_doc", rollup.aggregate_query("i", "a" * 24, 0, 600, root, [], True)
        )
        for bad in (
            ("adm summary", "a" * 24, root),
            ("i", "zz", root),
            ("i", "a" * 24, 'r" OR 1'),
        ):
            with self.assertRaises(rollup.SummaryError):
                rollup.manifest_query(bad[0], bad[1], 0, 600, bad[2])
        with self.assertRaises(rollup.SummaryError):
            rollup.aggregate_query("i", "a" * 24, 0, 600, root, ["x;"])

    def test_documents_are_flat_quote_free_scalars(self):
        identity, native = scenario()
        for doc in summary_docs(identity, native, WINDOWS):
            for key, value in doc.items():
                self.assertIsInstance(value, (str, int, float), key)
                self.assertFalse(
                    isinstance(value, str) and ('"' in value or "\n" in value)
                )
                self.assertLess(len(str(value)), 9000, key)

    def test_payloads_are_bounded(self):
        with self.assertRaises(rollup.SummaryError):
            rollup.unpack(rollup.pack("x" * 5000), limit=100)
        with self.assertRaises(rollup.SummaryError):
            rollup.unpack("not base64!")
        with self.assertRaises(rollup.SummaryError):
            rollup.slices_of(10, 310)


if __name__ == "__main__":
    unittest.main()
