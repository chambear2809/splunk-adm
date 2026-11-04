"""Actual HEC span shape and adversarial complete-snapshot identity evidence."""

import copy
import hashlib
import json
import unittest

from splunk_app.splunk_adm.bin.adm_identity_lib.protocol import canonical, owners_digest
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import graph_rows, qualify

PROFILE = {
    "enabled": True,
    "cluster": "cluster-a",
    "environment": "prod",
    "scope": "scope-a",
    "producer_id": "producer-a",
    "interval_index": "identity",
    "interval_source": "producer-a",
    "interval_sourcetype": "adm:pod_ip_interval:v2",
    "span_index": "traces",
    "span_source": "otel-a",
    "span_sourcetype": "otel:traces",
    "namespaces": ["shop"],
}


def row(raw, family="interval", receipt=40):
    return {
        "index": PROFILE[family + "_index"],
        "source": PROFILE[family + "_source"],
        "sourcetype": PROFILE[family + "_sourcetype"],
        "event_time": raw.get("observed_at", 15),
        "receipt_time": receipt,
        "_raw": json.dumps(raw),
    }


def interval_rows(
    identities=None, blocked=None, snapshot="snapshot-a", start=10, end=30
):
    shared = {
        "schema": "adm:pod_ip_interval:v2",
        "cluster": "cluster-a",
        "environment": "prod",
        "producer_id": "producer-a",
        "producer_epoch": "epoch-a",
        "valid_from": start,
        "valid_to": end,
        "observed_at": 35,
        "snapshot_id": snapshot,
    }
    owners = []
    for uid, ns, address in identities or [("uid-a", "shop", "10.0.0.1")]:
        owner = {
            **shared,
            "kind": "owner",
            "namespace": ns,
            "pod_uid": uid,
            "ip": address,
            "host_network": False,
            "node_name": "node-a",
            "operation": "present",
        }
        owner["record_id"] = hashlib.sha256(canonical(owner).encode()).hexdigest()
        owners.append(owner)
    manifest = {
        **shared,
        "kind": "manifest",
        "checkpoint_nonce": "nonce-a",
        "namespace_scope": "all",
        "expected_count": len(owners),
        "owners_sha256": owners_digest(owners),
        "invalidated_ips": blocked or [],
    }
    return [row(value) for value in [*owners, manifest]]


def span(
    service="checkout",
    sid="b",
    parent=None,
    kind="SERVER",
    uid="uid-a",
    start=12,
    end=20,
):
    raw = {
        "trace_id": "a" * 32,
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
    result = row(raw, "span")
    result["event_time"] = start
    return result


def mutate(value, **changes):
    value = copy.deepcopy(value)
    raw = json.loads(value["_raw"])
    raw.update(changes)
    value["_raw"] = json.dumps(raw)
    return value


class QualifiedIdentityTests(unittest.TestCase):
    def test_complete_actual_nanosecond_span_shape(self):
        result = qualify(interval_rows() + [span()], PROFILE, 0, 100)
        self.assertTrue(result["complete"], result)
        self.assertEqual(result["catalog_rows"][0]["pods"], 1)
        self.assertEqual(result["bindings"][0]["valid_from"], 12)
        self.assertEqual(result["bindings"][0]["valid_to"], 20)
        self.assertEqual(result["catalog_rows"][0]["identity_contract"], "qualified_v2")

    def test_missing_manifest_owner_or_changed_checksum_fails_closed(self):
        rows = interval_rows()
        for invalid in (
            rows[:1],
            rows[1:],
            [rows[0], mutate(rows[1], owners_sha256="bad")],
        ):
            result = qualify(invalid + [span()], PROFILE, 0, 100)
            self.assertFalse(result["complete"])
            self.assertEqual(result["catalog_rows"], [])

    def test_replay_is_immutable_and_counted_once(self):
        rows = interval_rows() + [span()]
        result = qualify(rows + copy.deepcopy(rows), PROFILE, 0, 100)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["bindings"]), 1)
        self.assertFalse(
            qualify(
                rows + [mutate(rows[1], checkpoint_nonce="other")], PROFILE, 0, 100
            )["complete"]
        )
        self.assertFalse(
            qualify(rows + [mutate(rows[2], name="changed")], PROFILE, 0, 100)[
                "complete"
            ]
        )

    def test_competing_namespace_and_invalidated_ip_never_qualify(self):
        for rows in (
            interval_rows(
                [("uid-a", "shop", "10.0.0.1"), ("uid-b", "other", "10.0.0.1")]
            ),
            interval_rows(blocked=["10.0.0.1"]),
        ):
            result = qualify(rows + [span()], PROFILE, 0, 100)
            self.assertTrue(result["complete"])
            self.assertEqual(result["catalog_rows"], [])

    def test_no_span_lifetime_extrapolation_or_seconds_timestamps(self):
        for invalid in (
            span(start=9),
            span(end=31),
            mutate(span(), start_time=12, end_time=20),
            mutate(span(), kind="server"),
        ):
            result = qualify(interval_rows() + [invalid], PROFILE, 0, 100)
            self.assertTrue(result["complete"])
            self.assertEqual(result["catalog_rows"], [])

    def test_authority_resources_and_budget_fail_closed(self):
        rows = interval_rows() + [span()]
        for invalid in (
            [mutate(rows[0], producer_id="other"), *rows[1:]],
            [*rows[:-1], mutate(rows[-1], **{"deployment.environment": "other"})],
        ):
            self.assertFalse(qualify(invalid, PROFILE, 0, 100)["complete"])
        self.assertFalse(qualify(rows, PROFILE, 0, 301)["complete"])
        self.assertFalse(
            qualify(rows, {**PROFILE, "enabled": False}, 0, 100)["complete"]
        )

    def test_late_snapshot_is_not_known_at_as_of(self):
        rows = interval_rows() + [span()]
        rows[1]["receipt_time"] = 101
        self.assertFalse(qualify(rows, PROFILE, 0, 100)["complete"])

    def test_dual_stack_is_retained_without_arbitrary_ip_selection(self):
        rows = interval_rows(
            [("uid-a", "shop", "10.0.0.1"), ("uid-a", "shop", "2001:db8::1")]
        )
        result = qualify(rows + [span()], PROFILE, 0, 100)
        self.assertEqual(
            result["bindings"][0]["ip_candidates"], ["10.0.0.1", "2001:db8::1"]
        )

    def test_collector_resource_copies_are_raw_and_conflicts_fail_closed(self):
        item = span()
        raw = json.loads(item["_raw"])
        raw["attributes"] = {}
        for key in list(raw):
            if "." in key:
                raw["attributes"]["atlas.resource." + key] = raw.pop(key)
        item["_raw"] = json.dumps(raw)
        result = qualify(interval_rows() + [item], PROFILE, 0, 100)
        self.assertEqual(len(result["bindings"]), 1)
        raw["service.name"] = "contradiction"
        item["_raw"] = json.dumps(raw)
        self.assertFalse(qualify(interval_rows() + [item], PROFILE, 0, 100)["complete"])

    def test_extracted_fields_cannot_establish_raw_identity(self):
        item = span()
        raw = json.loads(item["_raw"])
        for key in list(raw):
            if "." in key:
                item[key] = raw.pop(key)
        item["_raw"] = json.dumps(raw)
        self.assertFalse(qualify(interval_rows() + [item], PROFILE, 0, 100)["complete"])

    def test_overlapping_complete_empty_snapshot_refutes_owner(self):
        rows = interval_rows()
        manifest = json.loads(
            interval_rows(snapshot="snapshot-b", start=15, end=25)[-1]["_raw"]
        )
        manifest.update(expected_count=0, owners_sha256=owners_digest([]))
        self.assertFalse(
            qualify(rows + [row(manifest), span(start=16)], PROFILE, 0, 100)["complete"]
        )

    def test_host_network_does_not_establish_exclusive_pod_ip(self):
        rows = interval_rows()
        owner = json.loads(rows[0]["_raw"])
        owner["host_network"] = True
        owner.pop("record_id")
        owner["record_id"] = hashlib.sha256(canonical(owner).encode()).hexdigest()
        manifest = json.loads(rows[-1]["_raw"])
        manifest["owners_sha256"] = owners_digest([owner])
        result = qualify([row(owner), row(manifest), span()], PROFILE, 0, 100)
        self.assertTrue(result["complete"])
        self.assertEqual(result["bindings"], [])

    def test_parent_client_call_graph_preserves_scope_and_no_traffic_claims(self):
        rows = interval_rows() + [
            span("frontend", "c", kind="CLIENT"),
            span(parent="c"),
        ]
        result = qualify(rows, PROFILE, 0, 100)
        graph = graph_rows(result)
        edge = next(value for value in graph if value["row_type"] == "edge")
        self.assertEqual(edge["relationship"], "calls")
        self.assertEqual(edge["source"], "service:cluster-a/shop/frontend/prod")
        for key in ("bytes", "conns", "route"):
            self.assertNotIn(key, edge)
        self.assertFalse(
            any(
                value["row_type"] == "edge"
                for value in graph_rows(
                    qualify(interval_rows() + [span(parent="c")], PROFILE, 0, 100)
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
