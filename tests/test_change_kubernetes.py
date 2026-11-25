"""Focused tests for the offline Kubernetes and Cilium source adapters."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.change_correlation.adapters.kubernetes import (
    adapt_cilium_policies,
    adapt_endpointslices,
    adapt_kubernetes_watch,
    adapt_pods,
    adapt_services,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE_ROOT = (
    Path(__file__).resolve().parents[1] / "fixtures/change-correlation/kubernetes"
)


def fixture(name: str) -> object:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def metadata(
    *,
    capture_id: str = "capture-k8s-001",
    source_version: str = "Kubernetes 1.34.0",
    **updates: object,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": 1,
        "capture_id": capture_id,
        "authority": "cluster:synthetic-east",
        "source_version": source_version,
        "partition": "cluster:synthetic-east",
        "scope": "change-a",
        "started_at": 1_792_400_000,
        "completed_at": 1_792_400_005,
        "received_at": 1_792_400_006,
        "status": "complete",
        "permissions_fingerprint": "rbac:reviewed-fixture-v1",
        "pages_expected": 1,
        "pages_received": 1,
        "source_reference": f"capture:{capture_id}",
        "enumeration": "full",
        "deletions_authoritative": True,
    }
    result.update(updates)
    return result


def one_object(collection: dict[str, object]) -> dict[str, object]:
    objects = collection["objects"]
    assert isinstance(objects, list) and len(objects) == 1
    return objects[0]


class KubernetesListAdapterTests(unittest.TestCase):
    def test_service_selector_values_are_fingerprinted_and_ports_are_tuple_sorted(
        self,
    ) -> None:
        native = fixture("services-v1.json")
        baseline = adapt_services(native, metadata())
        baseline_object = one_object(baseline)
        fields = baseline_object["fields"]
        self.assertEqual(
            fields["selector_keys"],
            [
                "app.kubernetes.io/instance",
                "app.kubernetes.io/name",
            ],
        )
        self.assertNotIn("payments-api", canonical_json(fields).decode())
        self.assertEqual(
            fields["port_numbers"],
            [
                port["port"]
                for port in [
                    {"name": "https", "protocol": "TCP", "port": 443},
                    {"name": "metrics", "protocol": "UDP", "port": 9090},
                ]
            ],
        )
        self.assertEqual(fields["protocols"], ["TCP", "UDP"])
        self.assertEqual(fields["target_ports"], ["8443", "metrics"])
        self.assertEqual(fields["port_tuples"], sorted(fields["port_tuples"]))
        self.assertEqual(baseline_object["object_id"], "service-uid-01")
        self.assertEqual(baseline_object["revision"], "k8s-rv-101")

        reordered = copy.deepcopy(native)
        reordered["items"][0]["spec"]["ports"].reverse()
        reordered_collection = adapt_services(
            reordered, metadata(capture_id="capture-k8s-002")
        )
        self.assertEqual(
            one_object(reordered_collection)["fields"],
            fields,
            "native port reordering must not break port/protocol/target associations",
        )

        changed_selector = copy.deepcopy(native)
        changed_selector["items"][0]["spec"]["selector"]["app.kubernetes.io/name"] = (
            "payments-api-v2"
        )
        changed = adapt_services(
            changed_selector, metadata(capture_id="capture-k8s-003")
        )
        self.assertEqual(
            one_object(changed)["fields"]["selector_keys"],
            fields["selector_keys"],
        )
        self.assertNotEqual(
            one_object(changed)["fields"]["selector_digest"],
            fields["selector_digest"],
        )
        self.assertNotIn(
            "payments-api-v2", canonical_json(one_object(changed)["fields"]).decode()
        )

    def test_service_complete_empty_requires_a_real_complete_list(self) -> None:
        empty_list = {
            "apiVersion": "v1",
            "kind": "ServiceList",
            "metadata": {"resourceVersion": "opaque-rv-empty"},
            "items": [],
        }
        complete_empty = adapt_services(empty_list, metadata())
        self.assertEqual(complete_empty["status"], "complete")
        self.assertEqual(complete_empty["objects"], [])
        self.assertTrue(complete_empty["deletions_authoritative"])

        namespace_empty = adapt_services(
            empty_list,
            metadata(partition="namespace:shop", scope="change-a"),
        )
        self.assertEqual(namespace_empty["status"], "complete")
        self.assertEqual(namespace_empty["partition"], "namespace:shop")
        self.assertEqual(namespace_empty["scope"], "change-a")

        truncated = copy.deepcopy(empty_list)
        truncated["metadata"]["continue"] = "opaque-page-token"
        partial = adapt_services(truncated, metadata())
        self.assertEqual(partial["status"], "partial")
        self.assertFalse(partial["deletions_authoritative"])
        self.assertEqual(partial["pages_received"], 1)
        self.assertGreater(partial["pages_expected"], 1)

        incomplete_page_counts = adapt_services(
            empty_list,
            metadata(pages_expected=2, pages_received=1),
        )
        self.assertEqual(incomplete_page_counts["status"], "partial")
        self.assertFalse(incomplete_page_counts["deletions_authoritative"])

    def test_native_namespace_uses_partition_while_scope_stays_routing_scope(
        self,
    ) -> None:
        shop_service = copy.deepcopy(fixture("services-v1.json"))
        shop_service["items"][0]["metadata"]["namespace"] = "shop"
        result = adapt_services(
            shop_service,
            metadata(partition="namespace:shop", scope="change-a"),
        )
        self.assertEqual(result["partition"], "namespace:shop")
        self.assertEqual(result["scope"], "change-a")

        wrong_namespace = fixture("services-v1.json")
        with self.assertRaises(ContractError) as mismatch:
            adapt_services(
                wrong_namespace,
                metadata(partition="namespace:shop", scope="change-a"),
            )
        self.assertEqual(mismatch.exception.code, "partition_mismatch")

        wrong_cluster = fixture("services-v1.json")
        with self.assertRaises(ContractError) as cross_cluster:
            adapt_services(
                wrong_cluster,
                metadata(partition="cluster:synthetic-west", scope="change-a"),
            )
        self.assertEqual(cross_cluster.exception.code, "partition_mismatch")

    def test_malformed_or_unknown_lists_fail_closed(self) -> None:
        with self.assertRaises(ContractError):
            adapt_services(
                {"apiVersion": "v1", "kind": "List", "items": []}, metadata()
            )
        missing_items = {
            "apiVersion": "v1",
            "kind": "ServiceList",
            "metadata": {"resourceVersion": "1"},
        }
        with self.assertRaises(ContractError):
            adapt_services(missing_items, metadata())
        wrong_revision_type = fixture("services-v1.json")
        wrong_revision_type["items"][0]["metadata"]["resourceVersion"] = 101
        with self.assertRaises(ContractError):
            adapt_services(wrong_revision_type, metadata())

    def test_api_status_errors_are_failed_or_partial_receipts(self) -> None:
        status = fixture("watch-410-v1.json")["object"]
        expired = adapt_services(status, metadata(capture_id="capture-list-410"))
        self.assertEqual(expired["status"], "partial")
        self.assertEqual(expired["objects"], [])
        self.assertFalse(expired["deletions_authoritative"])
        self.assertIn("410-gone-relist-required", expired["source_reference"])

        denied_status = copy.deepcopy(status)
        denied_status["reason"] = "Forbidden"
        denied_status["code"] = 403
        denied = adapt_services(denied_status, metadata(capture_id="capture-list-403"))
        self.assertEqual(denied["status"], "failed")
        self.assertEqual(denied["objects"], [])

    def test_endpoint_slice_uses_qualified_pod_uids_and_marks_unknowns(self) -> None:
        native = fixture("endpointslices-v1.json")
        result = adapt_endpointslices(native, metadata())
        item = one_object(result)
        fields = item["fields"]
        self.assertEqual(item["object_id"], "slice-uid-01")
        self.assertEqual(fields["service_name"], "payments-api")
        self.assertEqual(fields["ready_backend_uids"], ["pod-uid-ready"])
        self.assertEqual(fields["not_ready_backend_uids"], ["pod-uid-not-ready"])
        self.assertEqual(fields["ready_count"], 1)
        self.assertEqual(fields["not_ready_count"], 1)
        self.assertEqual(fields["unresolved_endpoint_count"], 2)
        self.assertEqual(fields["ports"], [8443, 9090])
        self.assertEqual(fields["port_tuples"], sorted(fields["port_tuples"]))
        output = canonical_json(fields).decode()
        self.assertNotIn("192.0.2.", output)
        self.assertNotIn("pod-uid-readiness-unknown", output)

        reordered = copy.deepcopy(native)
        endpoint = reordered["items"][0]
        endpoint["ports"].reverse()
        endpoint["endpoints"].reverse()
        second = adapt_endpointslices(reordered, metadata(capture_id="capture-k8s-002"))
        self.assertEqual(one_object(second)["fields"], fields)

        wrong_target_kind = copy.deepcopy(native)
        wrong_target_kind["items"][0]["endpoints"][0]["targetRef"]["kind"] = "Node"
        third = adapt_endpointslices(
            wrong_target_kind, metadata(capture_id="capture-k8s-003")
        )
        self.assertEqual(one_object(third)["fields"]["ready_backend_uids"], [])
        self.assertEqual(one_object(third)["fields"]["unresolved_endpoint_count"], 3)

        conflicting_readiness = copy.deepcopy(native)
        conflicting_readiness["items"][0]["endpoints"].append(
            {
                "addresses": ["192.0.2.14"],
                "conditions": {"ready": False},
                "targetRef": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "name": "payments-api-7c49d",
                    "namespace": "payments",
                    "uid": "pod-uid-ready",
                },
            }
        )
        conflict_result = adapt_endpointslices(
            conflicting_readiness,
            metadata(capture_id="capture-k8s-004"),
        )
        conflict_fields = one_object(conflict_result)["fields"]
        self.assertEqual(conflict_fields["ready_backend_uids"], [])
        self.assertEqual(conflict_fields["unresolved_endpoint_count"], 4)

    def test_pod_snapshot_hashes_only_fixed_app_version_labels(self) -> None:
        native = fixture("pods-v1.json")
        collection = adapt_pods(native, metadata())
        item = one_object(collection)
        fields = item["fields"]
        self.assertEqual(collection["family"], "pod_snapshot")
        self.assertEqual(item["object_id"], "pod-uid-ready")
        self.assertEqual(fields["namespace"], "payments")
        self.assertEqual(fields["node_name"], "worker-a")
        self.assertEqual(fields["owner_kind"], "ReplicaSet")
        self.assertEqual(fields["owner_uid"], "replicaset-uid-01")
        self.assertEqual(fields["phase"], "Running")
        self.assertNotIn("ignore-me", canonical_json(fields).decode())
        self.assertNotIn("example.invalid/payments", canonical_json(fields).decode())

        unreviewed_label_change = copy.deepcopy(native)
        unreviewed_label_change["items"][0]["metadata"]["labels"][
            "private.example.invalid/contact"
        ] = "different"
        same_digest = adapt_pods(
            unreviewed_label_change, metadata(capture_id="capture-k8s-002")
        )
        self.assertEqual(
            one_object(same_digest)["fields"]["app_version_label_digest"],
            fields["app_version_label_digest"],
        )

        version_change = copy.deepcopy(native)
        version_change["items"][0]["metadata"]["labels"][
            "app.kubernetes.io/version"
        ] = "2.4.2"
        changed_digest = adapt_pods(
            version_change, metadata(capture_id="capture-k8s-003")
        )
        self.assertNotEqual(
            one_object(changed_digest)["fields"]["app_version_label_digest"],
            fields["app_version_label_digest"],
        )

    def test_cilium_requires_exact_qualified_v2_gvk_and_excludes_spec(self) -> None:
        native = fixture("cilium-policies-v2.json")
        inputs = metadata(
            source_version="Cilium 1.20.3",
            qualified_gvks=["cilium.io/v2/CiliumNetworkPolicy"],
        )
        result = adapt_cilium_policies(native, inputs)
        item = one_object(result)
        self.assertEqual(result["product"], "cilium")
        self.assertEqual(result["family"], "network_policy_snapshot")
        self.assertEqual(item["object_id"], "cilium-policy-uid-01")
        self.assertEqual(item["revision"], "k8s-rv-401")
        self.assertEqual(item["fields"]["generation"], 3)
        rendered = canonical_json(item["fields"]).decode()
        self.assertNotIn("allow-payments-ingress", rendered)
        self.assertNotIn("endpointSelector", rendered)
        self.assertNotIn("ingress", rendered)
        self.assertTrue(all("=" in label for label in item["fields"]["labels"]))

        with self.assertRaises(ContractError):
            adapt_cilium_policies(native, metadata(source_version="Cilium 1.20.3"))
        wrong_gvk = copy.deepcopy(native)
        wrong_gvk["items"][0]["apiVersion"] = "cilium.io/v3"
        with self.assertRaises(ContractError):
            adapt_cilium_policies(wrong_gvk, inputs)

    def test_cilium_list_items_must_match_declared_list_kind(self) -> None:
        native = fixture("cilium-policies-v2.json")
        native["items"][0]["kind"] = "CiliumClusterwideNetworkPolicy"
        inputs = metadata(
            source_version="Cilium 1.20.3",
            qualified_gvks=["cilium.io/v2/CiliumNetworkPolicy"],
        )
        with self.assertRaises(ContractError) as caught:
            adapt_cilium_policies(native, inputs)
        self.assertEqual(caught.exception.code, "unknown_resource_kind")

        native = fixture("cilium-policies-v2.json")
        native["items"][0]["apiVersion"] = "cilium.io/v3"
        with self.assertRaises(ContractError) as caught:
            adapt_cilium_policies(native, inputs)
        self.assertEqual(caught.exception.code, "unknown_resource_kind")

    def test_cilium_policy_families_prevent_cross_kind_false_removals(self) -> None:
        cnp = fixture("cilium-policies-v2.json")
        cnp_metadata = metadata(
            capture_id="capture-cnp-001",
            qualified_gvks=["cilium.io/v2/CiliumNetworkPolicy"],
        )
        cnp_receipt = adapt_cilium_policies(cnp, cnp_metadata)
        ccnp = copy.deepcopy(cnp)
        ccnp["kind"] = "CiliumClusterwideNetworkPolicyList"
        ccnp["items"] = []
        ccnp_metadata = metadata(
            capture_id="capture-ccnp-002",
            started_at=1_792_400_100,
            completed_at=1_792_400_105,
            received_at=1_792_400_106,
            qualified_gvks=["cilium.io/v2/CiliumClusterwideNetworkPolicy"],
        )
        ccnp_receipt = adapt_cilium_policies(ccnp, ccnp_metadata)

        generation = build_generation([cnp_receipt, ccnp_receipt])
        self.assertFalse(
            any(
                row["record_type"] == "change" and row["change_type"] == "removed"
                for row in generation["rows"]
            )
        )

    def test_cilium_status_errors_are_typed_and_reject_ambiguous_errors(self) -> None:
        status = fixture("watch-410-v1.json")["object"]
        with self.assertRaises(ContractError) as caught:
            adapt_cilium_policies(status, metadata())
        self.assertEqual(caught.exception.code, "ambiguous_native_error")

        result = adapt_cilium_policies(
            status,
            metadata(
                expected_resource_kind="CiliumNetworkPolicy",
                qualified_gvks=["cilium.io/v2/CiliumNetworkPolicy"],
            ),
        )
        self.assertEqual(result["family"], "network_policy_snapshot")

    def test_cilium_clusterwide_policy_requires_cluster_partition(self) -> None:
        native = {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumClusterwideNetworkPolicyList",
            "metadata": {"resourceVersion": "opaque-list-rv"},
            "items": [
                {
                    "apiVersion": "cilium.io/v2",
                    "kind": "CiliumClusterwideNetworkPolicy",
                    "metadata": {
                        "name": "cluster-policy",
                        "uid": "cluster-policy-uid",
                        "resourceVersion": "opaque-object-rv",
                        "generation": 1,
                    },
                    "spec": {"endpointSelector": {"matchLabels": {"role": "db"}}},
                }
            ],
        }
        inputs = metadata(
            source_version="Cilium 1.20.3",
            qualified_gvks=["cilium.io/v2/CiliumClusterwideNetworkPolicy"],
            scope="namespace:payments",
        )
        result = adapt_cilium_policies(native, inputs)
        self.assertEqual(one_object(result)["fields"]["namespace"], None)
        self.assertEqual(result["scope"], "namespace:payments")
        with self.assertRaises(ContractError):
            adapt_cilium_policies(
                native,
                metadata(
                    partition="namespace:payments",
                    qualified_gvks=["cilium.io/v2/CiliumClusterwideNetworkPolicy"],
                ),
            )


class KubernetesWatchAdapterTests(unittest.TestCase):
    def test_watch_receipt_preserves_deleted_uid_without_claiming_removal(self) -> None:
        watch_metadata = metadata(
            capture_id="capture-watch-001",
            enumeration="incremental",
            deletions_authoritative=True,
            watch_contiguous=True,
            watch_ended=True,
            start_resource_version="opaque-start-rv",
        )
        collection = adapt_services(fixture("watch-events-v1.json"), watch_metadata)
        self.assertEqual(collection["family"], "object_watch")
        self.assertEqual(collection["status"], "complete")
        self.assertEqual(collection["scope"], "change-a")
        self.assertEqual(collection["enumeration"], "incremental")
        self.assertFalse(collection["deletions_authoritative"])
        events = {item["fields"]["event_type"]: item for item in collection["objects"]}
        self.assertEqual(set(events), {"MODIFIED", "DELETED"})
        deleted = events["DELETED"]
        self.assertEqual(deleted["fields"]["resource_uid"], "service-uid-old")
        self.assertEqual(deleted["revision"], "k8s-rv-502")
        self.assertNotEqual(deleted["object_id"], deleted["fields"]["resource_uid"])
        self.assertNotIn("payments-api-old", canonical_json(deleted["fields"]).decode())

    def test_watch_without_initial_state_or_cursor_is_partial(self) -> None:
        result = adapt_services(
            fixture("watch-events-v1.json"),
            metadata(
                capture_id="capture-watch-partial",
                enumeration="incremental",
                watch_contiguous=True,
                watch_ended=True,
            ),
        )
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["deletions_authoritative"])

        with self.assertRaises(ContractError):
            adapt_services(
                fixture("watch-events-v1.json"),
                metadata(
                    capture_id="capture-watch-invalid-attestation",
                    enumeration="incremental",
                    watch_contiguous=True,
                    watch_ended=True,
                    initial_state_complete="false",
                ),
            )

    def test_410_gone_becomes_gap_and_requires_relist(self) -> None:
        result = adapt_kubernetes_watch(
            fixture("watch-410-v1.json"),
            metadata(
                capture_id="capture-watch-410",
                enumeration="incremental",
                status="complete",
                watch_contiguous=True,
                watch_ended=True,
                start_resource_version="expired-rv",
                expected_resource_kind="Service",
            ),
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["objects"], [])
        self.assertFalse(result["deletions_authoritative"])
        self.assertIn("410-gone-relist-required", result["source_reference"])

        raw_status = fixture("watch-410-v1.json")["object"]
        direct_result = adapt_kubernetes_watch(
            raw_status,
            metadata(
                capture_id="capture-watch-410-direct",
                enumeration="incremental",
                status="complete",
                expected_resource_kind="Service",
            ),
            expected_resource_kind="Service",
        )
        self.assertEqual(direct_result["status"], "partial")

    def test_unknown_watch_types_and_unqualified_cilium_watch_fail_closed(self) -> None:
        unknown = {
            "type": "ADDED_TO_CACHE",
            "object": fixture("services-v1.json")["items"][0],
        }
        with self.assertRaises(ContractError):
            adapt_services(unknown, metadata())

        cilium_event = {
            "type": "MODIFIED",
            "object": fixture("cilium-policies-v2.json")["items"][0],
        }
        with self.assertRaises(ContractError):
            adapt_kubernetes_watch(
                cilium_event,
                metadata(expected_resource_kind="CiliumNetworkPolicy"),
            )


if __name__ == "__main__":
    unittest.main()
