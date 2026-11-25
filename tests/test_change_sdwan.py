"""Offline source-shape and safety tests for the SD-WAN audit adapter."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.change_correlation.adapters.sdwan import (
    FEATURE_DISPOSITIONS,
    adapt_sdwan_audits,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "change-correlation"
    / "sdwan"
    / "audit_log_documentation_shaped.json"
)
CAPABILITY_FIXTURE = FIXTURE.with_name("source_capabilities.json")

_EXPECTED_FEATURE_DISPOSITIONS = {
    "sdwan.template_changes": "adapter_tested_context_only",
    "sdwan.policy_changes": "adapter_tested_context_only",
    "sdwan.device_template_revisions": "blocked_native_object_revision_missing",
    "sdwan.deployment_action_status": "unsupported_in_audit_family",
    "sdwan.site_vpn_device": "blocked_native_site_vpn_binding_missing",
    "sdwan.routing_transport_aar_qos": "blocked_native_semantics_missing",
    "sdwan.tunnel_health": "unsupported_operational_family",
    "sdwan.exporter_sampling": "unsupported_history_not_verified",
    "sdwan.detail_completeness_retention": "blocked_source_sample_and_retention_missing",
}


def documentation_fixture() -> tuple[list[dict], dict]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if value["fixture_status"] != "documentation_shaped_synthetic_not_native_sample":
        raise AssertionError("SD-WAN fixture must retain its non-sample status.")
    return value["native_records"], value["collection_metadata"]


class SdwanAuditAdapterTests(unittest.TestCase):
    def test_documentation_shaped_record_has_typed_allowlisted_projection(self) -> None:
        native_records, metadata = documentation_fixture()

        receipt = adapt_sdwan_audits(native_records, metadata)

        self.assertEqual(receipt["product"], "sdwan")
        self.assertEqual(receipt["family"], "audit_log")
        self.assertEqual(receipt["source_version"], "26.1-doc-schema")
        self.assertEqual(
            receipt["authority"], "https://manager-synthetic.example.invalid"
        )
        self.assertEqual(receipt["partition"], "manager-tenant:synthetic-default")
        self.assertEqual(receipt["scope"], "change-b")
        self.assertEqual(receipt["enumeration"], "incremental")
        self.assertFalse(receipt["deletions_authoritative"])
        self.assertEqual(
            receipt["objects"],
            [
                {
                    "object_id": "918c6d64-729c-4304-b2c7-955a7c0e6a61",
                    "revision": None,
                    "observed_at": 1659003592,
                    "event_at": 1659003590.292,
                    "effective_at": None,
                    "kind": "audit",
                    "actor": "7b0e784d-daa9-4a93-8748-14aa94ec8c0d",
                    "fields": {
                        "device_id": "172.16.255.22",
                        "feature": "user",
                        "module": "user",
                        "tenant": "default",
                    },
                }
            ],
        )

    def test_reported_audit_time_remains_distinct_from_effective_time(self) -> None:
        native_records, metadata = documentation_fixture()

        generation = build_generation([adapt_sdwan_audits(native_records, metadata)])
        observation = next(
            row for row in generation["rows"] if row["record_type"] == "observation"
        )

        self.assertEqual(observation["event_at"], 1659003590.292)
        self.assertEqual(
            observation["time_qualification"], "source_event_time_reported"
        )
        self.assertTrue(observation["clock_uncertainty_unknown"])
        self.assertIsNone(observation["effective_at"])
        self.assertEqual(observation["change_type"], "observation")

    def test_raw_details_messages_config_and_unqualified_targets_never_project(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        native = copy.deepcopy(native_records[0])
        native.update(
            {
                "auditdetails": [
                    '{"password":"SYNTHETIC_SECRET_CANARY"}',
                    "https://example.invalid/?token=SYNTHETIC_TOKEN_CANARY",
                ],
                "logmessage": "SYNTHETIC_MESSAGE_CANARY",
                "logusersrcip": "SYNTHETIC_SOURCE_IP_CANARY",
                "audit_config_before": '{"secret":"SYNTHETIC_BEFORE_CANARY"}',
                "audit_config_after": '{"token":"SYNTHETIC_AFTER_CANARY"}',
                "site_id": "202",
                "vpn_id": "30",
                "template_id": "SYNTHETIC_TEMPLATE_ID",
                "policy_id": "SYNTHETIC_POLICY_ID",
                "deviceName": "SYNTHETIC_DEVICE_NAME",
                "unknownNested": {"secret": "SYNTHETIC_NESTED_CANARY"},
            }
        )

        receipt = adapt_sdwan_audits([native], metadata)
        encoded = canonical_json(receipt).decode("utf-8")
        fields = receipt["objects"][0]["fields"]

        for omitted in (
            "auditdetails",
            "logmessage",
            "logusersrcip",
            "audit_config_before",
            "audit_config_after",
            "site_id",
            "vpn_id",
            "template_id",
            "policy_id",
            "deviceName",
            "unknownNested",
            "SYNTHETIC_SECRET_CANARY",
            "SYNTHETIC_TOKEN_CANARY",
            "SYNTHETIC_MESSAGE_CANARY",
            "SYNTHETIC_SOURCE_IP_CANARY",
            "SYNTHETIC_BEFORE_CANARY",
            "SYNTHETIC_AFTER_CANARY",
            "SYNTHETIC_TEMPLATE_ID",
            "SYNTHETIC_POLICY_ID",
            "SYNTHETIC_DEVICE_NAME",
            "SYNTHETIC_NESTED_CANARY",
        ):
            self.assertNotIn(omitted, encoded)
        self.assertEqual(set(fields), {"device_id", "feature", "module", "tenant"})

    def test_ta_helper_json_string_shape_is_discarded_without_decoding(self) -> None:
        native_records, metadata = documentation_fixture()
        native = copy.deepcopy(native_records[0])
        native["auditdetails"] = '[{"credential":"SYNTHETIC_RAW_CANARY"}]'

        receipt = adapt_sdwan_audits([native], metadata)

        self.assertNotIn(
            "SYNTHETIC_RAW_CANARY", canonical_json(receipt).decode("utf-8")
        )

    def test_integer_epoch_milliseconds_are_exact_and_ambiguous_values_fail_closed(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        for value in (1659003590292.0, 1659003590292.1, "1659003590292", True, -1):
            with self.subTest(value_type=type(value).__name__, value=value):
                native = copy.deepcopy(native_records[0])
                native["entry_time"] = value
                with self.assertRaises(ContractError) as caught:
                    adapt_sdwan_audits([native], metadata)
                self.assertEqual(caught.exception.code, "invalid_time")
                self.assertNotIn(str(value), str(caught.exception))

    def test_native_audit_id_and_required_source_shapes_are_validated(self) -> None:
        native_records, metadata = documentation_fixture()
        for field, value, code in (
            ("logid", "not-a-uuid", "invalid_native_id"),
            ("logid", True, "invalid_native_field"),
            ("loguser", {"name": "admin"}, "invalid_native_field"),
            ("auditdetails", {"details": "unreviewed"}, "invalid_native_field"),
            ("logmessage", ["unreviewed"], "invalid_native_field"),
            ("statcycletime", True, "invalid_native_field"),
        ):
            with self.subTest(field=field, value_type=type(value).__name__):
                native = copy.deepcopy(native_records[0])
                native[field] = value
                with self.assertRaises(ContractError) as caught:
                    adapt_sdwan_audits([native], metadata)
                self.assertEqual(caught.exception.code, code)

        native = copy.deepcopy(native_records[0])
        native.pop("logid")
        with self.assertRaises(ContractError) as caught:
            adapt_sdwan_audits([native], metadata)
        self.assertEqual(caught.exception.code, "missing_native_field")

    def test_scope_and_native_partition_are_preserved_independently(self) -> None:
        native_records, metadata = documentation_fixture()
        metadata["partition"] = "manager-tenant:another-native-partition"
        metadata["scope"] = "change-b"

        receipt = adapt_sdwan_audits(native_records, metadata)

        self.assertEqual(
            receipt["partition"], "manager-tenant:another-native-partition"
        )
        self.assertEqual(receipt["scope"], "change-b")
        self.assertEqual(
            receipt["objects"][0]["object_id"],
            "918c6d64-729c-4304-b2c7-955a7c0e6a61",
        )
        self.assertEqual(receipt["objects"][0]["fields"]["tenant"], "default")

    def test_duplicate_native_ids_and_incomplete_page_receipts_fail_closed(
        self,
    ) -> None:
        native_records, metadata = documentation_fixture()
        duplicate = copy.deepcopy(native_records[0])
        with self.assertRaises(ContractError) as caught:
            adapt_sdwan_audits([native_records[0], duplicate], metadata)
        self.assertEqual(caught.exception.code, "duplicate_object_id")

        metadata["pages_expected"] = 2
        metadata["pages_received"] = 1
        with self.assertRaises(ContractError) as caught:
            adapt_sdwan_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "incomplete_receipt")

    def test_empty_page_is_valid_but_audit_history_cannot_claim_deletions(self) -> None:
        _, metadata = documentation_fixture()

        receipt = adapt_sdwan_audits([], metadata)

        self.assertEqual(receipt["objects"], [])
        self.assertFalse(receipt["deletions_authoritative"])
        metadata["deletions_authoritative"] = True
        with self.assertRaises(ContractError) as caught:
            adapt_sdwan_audits([], metadata)
        self.assertEqual(caught.exception.code, "invalid_deletion_authority")

    def test_all_nine_register_features_have_explicit_source_dispositions(self) -> None:
        register = json.loads(CAPABILITY_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(register["schema_version"], 1)
        self.assertEqual(register["source_family"], "sdwan")
        self.assertEqual(
            register["provenance"]["fixture_status"],
            "documentation_shaped_synthetic_not_native_sample",
        )
        registered_ids = set(register["features"])
        self.assertEqual(set(FEATURE_DISPOSITIONS), registered_ids)
        self.assertEqual(FEATURE_DISPOSITIONS, register["features"])
        self.assertEqual(FEATURE_DISPOSITIONS, _EXPECTED_FEATURE_DISPOSITIONS)
        self.assertEqual(len(FEATURE_DISPOSITIONS), 9)


if __name__ == "__main__":
    unittest.main()
