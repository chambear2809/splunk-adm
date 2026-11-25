"""Offline Catalyst Center and ISE source-schema boundary tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.change_correlation.adapters.catalyst import (
    FEATURE_DISPOSITIONS,
    ISE_FEATURE_DISPOSITIONS,
    adapt_catalyst_audits,
    adapt_ise_configuration_audits,
    adapt_ise_session_context,
    adapt_ise_sgt_snapshots,
    adapt_ise_sxp_bindings,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "change-correlation"
    / "catalyst"
    / "audit_log_documentation_shaped.json"
)

_EXPECTED_CATALYST_FEATURES = {
    "catalyst_center.audit_task_status",
    "catalyst_center.provisioning_templates",
    "catalyst_center.device_site_profile",
    "catalyst_center.software_activation",
    "catalyst_center.interface_client_vlan",
    "catalyst_center.network_device_identity",
    "catalyst_center.compliance_actual_diff",
    "catalyst_center.wireless_config",
    "catalyst_center.historical_bindings",
}
_ISE_ADAPTERS = {
    "ise_trustsec.configuration_audit": adapt_ise_configuration_audits,
    "ise_trustsec.sgt_definitions": adapt_ise_sgt_snapshots,
    "ise_trustsec.sxp_bindings": adapt_ise_sxp_bindings,
    "ise_trustsec.session_context": adapt_ise_session_context,
}


def documentation_fixture() -> tuple[dict, dict]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if value["fixture_status"] != "documentation_shaped_synthetic_not_native_sample":
        raise AssertionError("Catalyst fixture must remain explicitly synthetic.")
    return value["native_records"], value["collection_metadata"]


class CatalystAuditAdapterTests(unittest.TestCase):
    def test_documentation_shaped_audit_projects_only_frozen_fields(self) -> None:
        native_records, metadata = documentation_fixture()

        receipt = adapt_catalyst_audits(native_records, metadata)

        self.assertEqual(receipt["product"], "catalyst_center")
        self.assertEqual(receipt["family"], "audit_log")
        self.assertEqual(receipt["source_version"], metadata["source_version"])
        self.assertEqual(receipt["authority"], metadata["authority"])
        self.assertEqual(receipt["partition"], "controller-audit")
        self.assertEqual(receipt["scope"], "change-b")
        self.assertEqual(receipt["enumeration"], "incremental")
        self.assertFalse(receipt["deletions_authoritative"])
        self.assertEqual(
            receipt["objects"],
            [
                {
                    "object_id": "audit-instance-synthetic-001",
                    "revision": None,
                    "observed_at": 1793102402,
                    "event_at": 1793102400.123,
                    "effective_at": None,
                    "kind": "audit",
                    "actor": "synthetic-admin-01",
                    "fields": {
                        "parent_event_id": "audit-parent-synthetic-001",
                        "event_name": "updateConfigurationTemplate",
                        "event_type": "USER_EVENT",
                        "category": "INFO",
                        "domain": "Configuration",
                        "subdomain": "Template",
                        "source": "template-service",
                        "event_hierarchy": "US.CA.Synthetic",
                        "severity": 2,
                        "child_count": 1,
                    },
                }
            ],
        )

    def test_audit_identity_is_not_a_target_config_object_or_applied_revision(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        receipt = adapt_catalyst_audits(native_records, metadata)
        generation = build_generation([receipt])
        observation = next(
            row for row in generation["rows"] if row["record_type"] == "observation"
        )

        self.assertEqual(observation["object_id"], native_records[0]["instanceId"])
        self.assertEqual(observation["kind"], "audit")
        self.assertEqual(observation["change_type"], "observation")
        self.assertEqual(observation["event_at"], 1793102400.123)
        self.assertEqual(
            observation["time_qualification"], "source_event_time_reported"
        )
        self.assertTrue(observation["clock_uncertainty_unknown"])
        self.assertIsNone(observation["effective_at"])
        self.assertEqual(
            observation["projection_qualification"], "normalized_export_only"
        )
        self.assertTrue(observation["native_sample_unqualified"])

    def test_native_source_and_ta_renamed_src_are_supported_without_aliasing_network(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[0])
        record["source"] = record.pop("src")
        receipt = adapt_catalyst_audits([record], metadata)
        fields = receipt["objects"][0]["fields"]

        self.assertEqual(fields["source"], "template-service")
        self.assertNotIn("network_id", fields)
        self.assertNotIn("eventId", fields)
        self.assertEqual(receipt["objects"][0]["object_id"], record["instanceId"])

        record["src"] = "another-source"
        with self.assertRaises(ContractError) as caught:
            adapt_catalyst_audits([record], metadata)
        self.assertEqual(caught.exception.code, "ambiguous_native_field")

    def test_nested_details_links_and_unregistered_ids_never_reach_output(self) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[0])
        record["details"] = {
            "credential": "SYNTHETIC_SECRET_CANARY",
            "nested": {"token": "SYNTHETIC_TOKEN_CANARY"},
        }
        record["additionalDetails"] = "SYNTHETIC_ADDITIONAL_CANARY"
        record["message"] = "SYNTHETIC_MESSAGE_CANARY"
        record["description"] = "SYNTHETIC_DESCRIPTION_CANARY"
        record["ciscoDnaEventLink"] = (
            "https://example.invalid/?token=SYNTHETIC_URL_CANARY"
        )
        record["tenantId"] = "SYNTHETIC_TENANT_CANARY"
        record["eventId"] = "SYNTHETIC_EVENT_ID_CANARY"
        record["network"] = "SYNTHETIC_NETWORK_CANARY"

        encoded = canonical_json(adapt_catalyst_audits([record], metadata)).decode()

        for omitted in (
            "details",
            "additionalDetails",
            "message",
            "description",
            "ciscoDnaEventLink",
            "tenantId",
            "eventId",
            "network_id",
            "SYNTHETIC_SECRET_CANARY",
            "SYNTHETIC_TOKEN_CANARY",
            "SYNTHETIC_ADDITIONAL_CANARY",
            "SYNTHETIC_MESSAGE_CANARY",
            "SYNTHETIC_DESCRIPTION_CANARY",
            "SYNTHETIC_URL_CANARY",
            "SYNTHETIC_TENANT_CANARY",
            "SYNTHETIC_EVENT_ID_CANARY",
            "SYNTHETIC_NETWORK_CANARY",
        ):
            self.assertNotIn(omitted, encoded)

    def test_source_time_requires_integer_epoch_milliseconds(self) -> None:
        native_records, metadata = documentation_fixture()
        for value in (1793102400123.0, 1793102400123.1, "1793102400123", True, -1):
            with self.subTest(value_type=type(value).__name__, value=value):
                record = copy.deepcopy(native_records[0])
                record["timestamp"] = value
                with self.assertRaises(ContractError) as caught:
                    adapt_catalyst_audits([record], metadata)
                self.assertEqual(caught.exception.code, "invalid_time")
                self.assertNotIn(str(value), str(caught.exception))

    def test_missing_event_time_stays_unknown_and_receipt_time_is_not_substituted(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        record = copy.deepcopy(native_records[0])
        del record["timestamp"]

        receipt = adapt_catalyst_audits([record], metadata)
        generation = build_generation([receipt])
        observation = next(
            row for row in generation["rows"] if row["record_type"] == "observation"
        )

        self.assertIsNone(receipt["objects"][0]["event_at"])
        self.assertEqual(receipt["objects"][0]["observed_at"], metadata["received_at"])
        self.assertEqual(observation["time_qualification"], "unknown_source_time")
        self.assertTrue(observation["clock_uncertainty_unknown"])

    def test_instance_id_and_native_scalar_types_are_checked(self) -> None:
        native_records, metadata = documentation_fixture()
        for field, value, code in (
            ("instanceId", None, "missing_native_field"),
            ("instanceId", 1, "invalid_native_field"),
            ("name", {"nested": "value"}, "invalid_native_field"),
            ("severity", True, "invalid_native_field"),
            ("childCount", 1.5, "invalid_native_field"),
            ("childCount", 10**1000, "invalid_native_field"),
        ):
            with self.subTest(field=field, value=value):
                record = copy.deepcopy(native_records[0])
                record[field] = value
                with self.assertRaises(ContractError) as caught:
                    adapt_catalyst_audits([record], metadata)
                self.assertEqual(caught.exception.code, code)

    def test_duplicate_instance_ids_and_unqualified_receipts_fail_closed(self) -> None:
        native_records, metadata = documentation_fixture()
        with self.assertRaises(ContractError) as duplicate:
            adapt_catalyst_audits([native_records[0], native_records[0]], metadata)
        self.assertEqual(duplicate.exception.code, "duplicate_native_id")

        incomplete = dict(metadata, pages_expected=2, pages_received=1)
        with self.assertRaises(ContractError) as pages:
            adapt_catalyst_audits(native_records, incomplete)
        self.assertEqual(pages.exception.code, "incomplete_receipt")

        incomplete.update(status="partial", completed_at=None)
        partial = adapt_catalyst_audits(native_records, incomplete)
        self.assertEqual(partial["status"], "partial")
        self.assertFalse(partial["deletions_authoritative"])

        wrong_enumeration = dict(metadata, enumeration="full")
        with self.assertRaises(ContractError) as enumeration:
            adapt_catalyst_audits(native_records, wrong_enumeration)
        self.assertEqual(enumeration.exception.code, "invalid_enumeration")

        deletion_claim = dict(metadata, deletions_authoritative=True)
        with self.assertRaises(ContractError) as deletion:
            adapt_catalyst_audits(native_records, deletion_claim)
        self.assertEqual(deletion.exception.code, "invalid_deletion_authority")

    def test_every_catalyst_center_feature_has_an_explicit_audit_boundary(self) -> None:
        self.assertEqual(set(FEATURE_DISPOSITIONS), _EXPECTED_CATALYST_FEATURES)
        self.assertEqual(
            FEATURE_DISPOSITIONS["catalyst_center.audit_task_status"],
            "adapter_tested_generic_audit_only",
        )
        self.assertTrue(
            all(
                value.startswith(("blocked_", "unsupported_"))
                for key, value in FEATURE_DISPOSITIONS.items()
                if key != "catalyst_center.audit_task_status"
            )
        )


class IseNativeSchemaBoundaryTests(unittest.TestCase):
    def test_every_ise_feature_has_an_explicit_blocked_disposition(self) -> None:
        self.assertEqual(set(ISE_FEATURE_DISPOSITIONS), set(_ISE_ADAPTERS))
        self.assertEqual(
            ISE_FEATURE_DISPOSITIONS["ise_trustsec.session_context"],
            "unsupported_operational_context_not_config_history",
        )
        self.assertTrue(
            all(
                value.startswith(("blocked_", "unsupported_"))
                for value in ISE_FEATURE_DISPOSITIONS.values()
            )
        )

    def test_unqualified_ise_payloads_are_rejected_without_echoing_source_data(
        self,
    ) -> None:
        sensitive = [{"MODIFIED_PROPERTIES": "SYNTHETIC_SECRET_CANARY"}]
        for feature_id, adapter in _ISE_ADAPTERS.items():
            with self.subTest(feature=feature_id):
                with self.assertRaises(ContractError) as caught:
                    adapter(sensitive, {"admin": "SYNTHETIC_ADMIN_CANARY"})
                self.assertEqual(caught.exception.code, "unsupported_source_schema")
                self.assertNotIn("SYNTHETIC_SECRET_CANARY", str(caught.exception))
                self.assertNotIn("SYNTHETIC_ADMIN_CANARY", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
