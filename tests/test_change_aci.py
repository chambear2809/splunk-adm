"""Offline source-shape and safety tests for the ACI audit adapter."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.change_correlation.adapters.aci import (
    adapt_aci_audits,
    adapt_aci_policy_snapshots,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "change-correlation"
    / "aci"
    / "aaa_mod_lr_documentation_shaped.json"
)


def documentation_fixture() -> tuple[dict, dict]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return value["native_records"], value["collection_metadata"]


def policy_documentation_fixture(family: str) -> tuple[dict, dict]:
    value = json.loads(
        (FIXTURE.parent / "policy_snapshots_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )
    snapshot = value["snapshots"][family]
    return snapshot["native_records"], snapshot["collection_metadata"]


class AciAuditAdapterTests(unittest.TestCase):
    def test_documentation_shaped_apic_and_ta_records_have_golden_projection(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()

        receipt = adapt_aci_audits(native_records, metadata)

        self.assertEqual(receipt["product"], "aci")
        self.assertEqual(receipt["family"], "aaa_mod_lr")
        self.assertEqual(receipt["enumeration"], "incremental")
        self.assertFalse(receipt["deletions_authoritative"])
        self.assertEqual(
            receipt["objects"],
            [
                {
                    "object_id": "9000000000000001",
                    "revision": None,
                    "observed_at": 1793102403,
                    "event_at": 1793102400.123,
                    "effective_at": None,
                    "kind": "audit",
                    "actor": "synthetic-admin",
                    "fields": {
                        "affected_dn": "uni/tn-synthetic/ap-web",
                        "event_code": "E4205000",
                        "operation": "modification",
                        "trigger": "config",
                        "transaction_id": "9007199254740993",
                    },
                },
                {
                    "object_id": "9000000000000002",
                    "revision": None,
                    "observed_at": 1793102403,
                    "event_at": 1793102401,
                    "effective_at": None,
                    "kind": "audit",
                    "actor": "synthetic-operator",
                    "fields": {
                        "affected_dn": "uni/tn-synthetic/ap-web/epg-web",
                        "event_code": "E4205001",
                        "operation": "creation",
                        "trigger": "config",
                        "transaction_id": "9007199254740994",
                    },
                },
            ],
        )

    def test_source_event_time_precision_and_unknown_clock_are_preserved(self) -> None:
        native_records, metadata = documentation_fixture()
        receipt = adapt_aci_audits(native_records[:1], metadata)

        generation = build_generation([receipt])
        observation = generation["rows"][0]
        self.assertEqual(observation["event_at"], 1793102400.123)
        self.assertEqual(
            observation["time_qualification"], "source_event_time_reported"
        )
        self.assertTrue(observation["clock_uncertainty_unknown"])
        self.assertIsNone(observation["effective_at"])

    def test_missing_native_time_is_not_inferred_from_ta_ingest_time(self) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[1])
        record.pop("created")
        record["_time"] = 1793102401

        receipt = adapt_aci_audits([record], metadata)
        generation = build_generation([receipt])

        self.assertIsNone(receipt["objects"][0]["event_at"])
        self.assertEqual(
            generation["rows"][0]["time_qualification"], "unknown_source_time"
        )
        self.assertTrue(generation["rows"][0]["clock_uncertainty_unknown"])

    def test_unknown_and_sensitive_fields_are_never_projected_or_inspected(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        first = native_records[0]["aaaModLR"]["attributes"]
        first.update(
            {
                "changeSet": {"credential": "SYNTHETIC_SECRET_CANARY"},
                "rawdetails": "https://example.invalid/?token=SYNTHETIC_TOKEN",
                "sessionId": "SYNTHETIC_SESSION",
                "descr": "SYNTHETIC_DESCRIPTION",
                "password": "SYNTHETIC_PASSWORD",
                "before": {"unreviewed": ["SYNTHETIC_BEFORE"]},
                "after": {"unreviewed": ["SYNTHETIC_AFTER"]},
                "url": "https://example.invalid/path",
            }
        )

        receipt = adapt_aci_audits(native_records, metadata)
        encoded = canonical_json(receipt).decode("utf-8")

        for omitted in (
            "changeSet",
            "rawdetails",
            "sessionId",
            "descr",
            "password",
            "before",
            "after",
            "url",
            "SYNTHETIC_SECRET_CANARY",
            "SYNTHETIC_TOKEN",
            "SYNTHETIC_SESSION",
            "SYNTHETIC_PASSWORD",
            "SYNTHETIC_BEFORE",
            "SYNTHETIC_AFTER",
        ):
            self.assertNotIn(omitted, encoded)

    def test_wrong_ta_authority_is_rejected(self) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[1])
        record["apic_host"] = "other-apic.example.invalid"

        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits([record], metadata)
        self.assertEqual(caught.exception.code, "wrong_authority")

        record.pop("apic_host")
        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits([record], metadata)
        self.assertEqual(caught.exception.code, "missing_native_authority")

    def test_complete_receipt_rejects_partial_pages_and_partial_receipt_is_explicit(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        metadata["pages_expected"] = 2
        metadata["pages_received"] = 1

        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "incomplete_receipt")

        metadata["status"] = "partial"
        metadata["completed_at"] = None
        receipt = adapt_aci_audits(native_records, metadata)
        self.assertEqual(receipt["status"], "partial")
        self.assertEqual((receipt["pages_expected"], receipt["pages_received"]), (2, 1))
        generation = build_generation([receipt])
        self.assertTrue(generation["rows"][0]["gap"])
        self.assertFalse(generation["rows"][0]["coverage_complete"])

    def test_duplicate_native_ids_fail_closed_for_complete_and_partial_receipts(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        duplicate = copy.deepcopy(native_records[0])

        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits([native_records[0], duplicate], metadata)
        self.assertEqual(caught.exception.code, "duplicate_object_id")

        duplicate["aaaModLR"]["attributes"]["ind"] = "deletion"
        partial_metadata = {**metadata, "status": "partial", "completed_at": None}
        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits([native_records[0], duplicate], partial_metadata)
        self.assertEqual(caught.exception.code, "conflicting_observation")

    def test_wrong_family_and_authoritative_deletions_are_rejected(self) -> None:
        native_records, metadata = documentation_fixture()
        metadata["family"] = "other"
        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "wrong_family")

        metadata["family"] = "aaa_mod_lr"
        metadata["deletions_authoritative"] = True
        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "invalid_deletion_authority")

    def test_missing_affected_dn_stays_missing_and_is_not_taken_from_audit_dn(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[0])
        attributes = record["aaaModLR"]["attributes"]
        attributes.pop("affected")
        attributes["dn"] = "subj-[uni/tn-synthetic/wrong-target]/mod-native-id"

        receipt = adapt_aci_audits([record], metadata)

        self.assertNotIn("affected_dn", receipt["objects"][0]["fields"])
        self.assertNotIn("dn", receipt["objects"][0]["fields"])

    def test_native_identity_is_required_and_boolean_ids_are_not_coerced(self) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[0])
        record["aaaModLR"]["attributes"].pop("id")
        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits([record], metadata)
        self.assertEqual(caught.exception.code, "missing_native_id")

        record["aaaModLR"]["attributes"]["id"] = True
        with self.assertRaises(ContractError) as caught:
            adapt_aci_audits([record], metadata)
        self.assertEqual(caught.exception.code, "invalid_native_field")


class AciPolicySnapshotAdapterTests(unittest.TestCase):
    def test_filter_entry_uses_native_dn_parent_and_scalar_fields(self) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")

        receipt = adapt_aci_policy_snapshots(native_records, metadata)

        self.assertEqual(receipt["family"], "filter_entry_snapshot")
        self.assertEqual(receipt["source_version"], metadata["source_version"])
        self.assertEqual(
            receipt["objects"][0],
            {
                "object_id": "uni/tn-synthetic/flt-Http/e-e1",
                "revision": None,
                "observed_at": 1793102403,
                "event_at": None,
                "effective_at": None,
                "kind": "configuration",
                "actor": None,
                "fields": {
                    "object_class": "vzEntry",
                    "name": "e1",
                    "parent_dn": "uni/tn-synthetic/flt-Http",
                    "ether_type": "ipv4",
                    "protocol": "tcp",
                    "source_from_port": "unspecified",
                    "source_to_port": "unspecified",
                    "destination_from_port": "80",
                    "destination_to_port": "80",
                },
            },
        )
        self.assertNotIn(b"SYNTHETIC_UNREVIEWED_ATTRIBUTE", canonical_json(receipt))

    def test_contract_subject_and_filter_reference_are_separate_native_objects(
        self,
    ) -> None:
        native_records, metadata = policy_documentation_fixture(
            "contract_subject_snapshot"
        )

        receipt = adapt_aci_policy_snapshots(native_records, metadata)
        by_class = {item["fields"]["object_class"]: item for item in receipt["objects"]}

        self.assertEqual(set(by_class), {"vzSubj", "vzRsSubjFiltAtt"})
        subject = by_class["vzSubj"]
        self.assertEqual(subject["object_id"], "uni/tn-synthetic/brc-web/subj-http")
        self.assertEqual(
            subject["fields"],
            {
                "object_class": "vzSubj",
                "name": "http",
                "parent_dn": "uni/tn-synthetic/brc-web",
                "reverse_filter_ports": "true",
                "provider_match_type": "All",
            },
        )
        reference = by_class["vzRsSubjFiltAtt"]
        self.assertEqual(
            reference["object_id"],
            "uni/tn-synthetic/brc-web/subj-http/rssubjFiltAtt-Http",
        )
        self.assertEqual(
            reference["fields"],
            {
                "object_class": "vzRsSubjFiltAtt",
                "parent_dn": "uni/tn-synthetic/brc-web/subj-http",
                "target_dn": "uni/tn-synthetic/flt-Http",
                "filter_name": "Http",
            },
        )

    def test_filter_name_does_not_reconstruct_a_missing_target_dn(self) -> None:
        native_records, metadata = policy_documentation_fixture(
            "contract_subject_snapshot"
        )
        relation = native_records[0]["vzBrCP"]["children"][0]["vzSubj"]["children"][0]
        attributes = relation["vzRsSubjFiltAtt"]["attributes"]
        attributes.pop("tDn")

        receipt = adapt_aci_policy_snapshots(native_records, metadata)
        reference = next(
            item
            for item in receipt["objects"]
            if item["fields"]["object_class"] == "vzRsSubjFiltAtt"
        )

        self.assertEqual(reference["fields"]["filter_name"], "Http")
        self.assertNotIn("target_dn", reference["fields"])

    def test_epg_attachment_keeps_native_reference_role_and_single_label(self) -> None:
        native_records, metadata = policy_documentation_fixture(
            "epg_contract_attachment_snapshot"
        )

        receipt = adapt_aci_policy_snapshots(native_records, metadata)

        self.assertEqual(
            receipt["objects"][0]["object_id"],
            "uni/tn-synthetic/ap-web/epg-app/rscons-web",
        )
        self.assertEqual(
            receipt["objects"][0]["fields"],
            {
                "object_class": "fvRsCons",
                "parent_dn": "uni/tn-synthetic/ap-web/epg-app",
                "role": "consumer",
                "target_dn": "uni/tn-synthetic/brc-web",
                "contract_name": "web",
                "match_label": "openCons",
            },
        )

    def test_multiple_attachment_labels_are_not_collapsed_into_one_scalar(self) -> None:
        native_records, metadata = policy_documentation_fixture(
            "epg_contract_attachment_snapshot"
        )
        relation = native_records[0]["fvAEPg"]["children"][1]["fvRsCons"]
        relation["children"].append({"vzConsLbl": {"attributes": {"name": "green"}}})

        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots(native_records, metadata)
        self.assertEqual(caught.exception.code, "multiple_attachment_labels")

    def test_entry_input_order_does_not_create_configuration_changes(self) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")
        second_entry = {
            "vzEntry": {
                "attributes": {
                    "dn": "uni/tn-synthetic/flt-Http/e-e2",
                    "name": "e2",
                    "etherT": "ipv4",
                    "prot": "tcp",
                    "dFromPort": "443",
                    "dToPort": "443",
                }
            }
        }
        native_records[0]["vzFilter"]["children"].append(second_entry)
        first = adapt_aci_policy_snapshots(native_records, metadata)
        next_metadata = {
            **metadata,
            "capture_id": "aci-filter-synthetic-002",
            "started_at": 1793102500,
            "completed_at": 1793102502,
            "received_at": 1793102503,
            "source_reference": "test-fixture:aci-policy-filter-next",
        }
        native_records[0]["vzFilter"]["children"].reverse()
        second = adapt_aci_policy_snapshots(native_records, next_metadata)

        def semantic_objects(receipt: dict) -> list[tuple[str, dict]]:
            return [(item["object_id"], item["fields"]) for item in receipt["objects"]]

        self.assertEqual(semantic_objects(first), semantic_objects(second))
        generation = build_generation([first, second])
        self.assertFalse(
            any(row["record_type"] == "change" for row in generation["rows"])
        )

    def test_explicit_complete_full_enumeration_can_record_an_entry_removal(
        self,
    ) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")
        first = adapt_aci_policy_snapshots(native_records, metadata)
        empty_filter = copy.deepcopy(native_records)
        empty_filter[0]["vzFilter"]["children"] = []
        next_metadata = {
            **metadata,
            "capture_id": "aci-filter-synthetic-dropped-entry",
            "started_at": 1793102500,
            "completed_at": 1793102502,
            "received_at": 1793102503,
            "source_reference": "test-fixture:aci-policy-filter-drop",
        }

        second = adapt_aci_policy_snapshots(empty_filter, next_metadata)
        generation = build_generation([first, second])
        deleted = [
            row
            for row in generation["rows"]
            if row["record_type"] == "change" and row["change_type"] == "removed"
        ]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["object_id"], "uni/tn-synthetic/flt-Http/e-e1")

    def test_unknown_class_error_objects_and_incomplete_pages_fail_closed(self) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")
        unknown_class = [{"unknownClass": {"attributes": {"dn": "native-dn"}}}]
        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots(unknown_class, metadata)
        self.assertEqual(caught.exception.code, "unsupported_native_class")

        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots([{"error": {"code": "synthetic"}}], metadata)
        self.assertEqual(caught.exception.code, "native_source_error")

        partial_metadata = {**metadata, "pages_expected": 2, "pages_received": 1}
        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots(native_records, partial_metadata)
        self.assertEqual(caught.exception.code, "incomplete_receipt")

        partial_metadata["status"] = "partial"
        partial_metadata["completed_at"] = None
        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots(native_records, partial_metadata)
        self.assertEqual(caught.exception.code, "invalid_deletion_authority")

        partial_metadata["deletions_authoritative"] = False
        receipt = adapt_aci_policy_snapshots(native_records, partial_metadata)
        self.assertEqual(receipt["status"], "partial")
        self.assertFalse(receipt["deletions_authoritative"])
        generation = build_generation([receipt])
        self.assertTrue(generation["rows"][0]["gap"])

    def test_parent_dn_is_not_synthesized_for_flat_class_queries(self) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")
        entry = native_records[0]["vzFilter"]["children"][0]["vzEntry"]["attributes"]
        flat_record = {
            "component": "vzEntry",
            **entry,
            "apic_host": "apic.example.invalid",
        }

        receipt = adapt_aci_policy_snapshots([flat_record], metadata)

        self.assertNotIn("parent_dn", receipt["objects"][0]["fields"])

    def test_flattened_container_fails_closed_without_child_completeness(self) -> None:
        _, metadata = policy_documentation_fixture("filter_entry_snapshot")
        flattened_filter = {
            "component": "vzFilter",
            "dn": "uni/tn-Synthetic/flt-filter",
            "name": "filter",
            "apic_host": "apic.example.invalid",
        }

        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots([flattened_filter], metadata)

        self.assertEqual(caught.exception.code, "incomplete_native_record")

    def test_deep_ignored_native_attributes_do_not_recurse(self) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")
        value: dict[str, object] = {"leaf": "ignored"}
        for _ in range(2000):
            value = {"nested": value}
        native_records[0]["vzFilter"]["attributes"]["ignored"] = value

        receipt = adapt_aci_policy_snapshots(native_records, metadata)

        self.assertEqual(len(receipt["objects"]), 1)

    def test_rejected_flattened_update_cannot_create_false_removal(self) -> None:
        native_records, metadata = policy_documentation_fixture("filter_entry_snapshot")
        first = adapt_aci_policy_snapshots(native_records, metadata)
        flattened_update = {
            "component": "vzFilter",
            "dn": "uni/tn-synthetic/flt-Http",
            "name": "Http",
            "apic_host": "apic.example.invalid",
        }
        next_metadata = {
            **metadata,
            "capture_id": "aci-filter-flattened-update",
            "source_reference": "test-fixture:aci-filter-flattened-update",
        }

        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots([flattened_update], next_metadata)
        self.assertEqual(caught.exception.code, "incomplete_native_record")

        generation = build_generation([first])
        self.assertFalse(any(row["record_type"] == "change" for row in generation["rows"]))

    def test_nested_flattened_child_authority_is_checked(self) -> None:
        native_records, metadata = policy_documentation_fixture(
            "filter_entry_snapshot"
        )
        native_records[0]["vzFilter"]["children"][0] = {
            "component": "vzEntry",
            "dn": "uni/tn-Synthetic/flt-filter/e-entry",
            "name": "entry",
            "apic_host": "other-apic.example.invalid",
        }

        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots(native_records, metadata)

        self.assertEqual(caught.exception.code, "wrong_authority")

    def test_policy_references_reject_urls_and_unknown_children(self) -> None:
        native_records, metadata = policy_documentation_fixture(
            "contract_subject_snapshot"
        )
        relation = native_records[0]["vzBrCP"]["children"][0]["vzSubj"]["children"][0]
        relation["vzRsSubjFiltAtt"]["attributes"]["tDn"] = (
            "https://example.invalid/?token=SYNTHETIC_TOKEN"
        )
        with self.assertRaises(ContractError):
            adapt_aci_policy_snapshots(native_records, metadata)

        native_records, metadata = policy_documentation_fixture(
            "contract_subject_snapshot"
        )
        native_records[0]["vzBrCP"]["children"][0]["vzSubj"]["children"].append(
            {"vzRsSubjGraphAtt": {"attributes": {"dn": "synthetic-graph-ref"}}}
        )
        with self.assertRaises(ContractError) as caught:
            adapt_aci_policy_snapshots(native_records, metadata)
        self.assertEqual(caught.exception.code, "unsupported_native_class")


if __name__ == "__main__":
    unittest.main()
