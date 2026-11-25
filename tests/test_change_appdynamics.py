"""Offline source-shape and privacy tests for the AppDynamics audit adapter."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.change_correlation.adapters.appdynamics import (
    FEATURE_DISPOSITIONS,
    adapt_appdynamics_audits,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE_DIR = (
    Path(__file__).parents[1] / "fixtures" / "change-correlation" / "appdynamics"
)


def audit_fixture() -> tuple[list[dict], dict]:
    value = json.loads(
        (FIXTURE_DIR / "audit_history_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )
    return value["native_records"], value["collection_metadata"]


class AppDynamicsAuditAdapterTests(unittest.TestCase):
    def test_documentation_shaped_rows_have_safe_typed_projection(self) -> None:
        native_records, metadata = audit_fixture()

        receipt = adapt_appdynamics_audits(native_records, metadata)

        self.assertEqual(receipt["product"], "appdynamics")
        self.assertEqual(receipt["family"], "audit_log")
        self.assertEqual(receipt["authority"], "controller-synthetic")
        self.assertEqual(receipt["partition"], "controller-synthetic")
        self.assertEqual(receipt["scope"], "change-a")
        self.assertEqual(receipt["enumeration"], "incremental")
        self.assertFalse(receipt["deletions_authoritative"])
        self.assertEqual(len(receipt["objects"]), 2)

        by_action = {obj["fields"]["action"]: obj for obj in receipt["objects"]}
        self.assertEqual(by_action["LOGIN"]["event_at"], 1793102400.25)
        self.assertEqual(by_action["LOGIN"]["actor"], "synthetic-user-01")
        self.assertEqual(
            by_action["LOGIN"]["fields"],
            {
                "account_name": "account-synthetic",
                "action": "LOGIN",
                "security_provider_type": "INTERNAL",
            },
        )
        self.assertEqual(
            by_action["APP_CONFIGURATION"]["fields"],
            {
                "account_name": "account-synthetic",
                "action": "APP_CONFIGURATION",
                "object_name": "Synthetic Application",
                "object_type": "APPLICATION",
                "security_provider_type": "INTERNAL",
            },
        )
        self.assertEqual(len(by_action["APP_CONFIGURATION"]["object_id"]), 64)
        self.assertIsNone(by_action["APP_CONFIGURATION"]["effective_at"])

    def test_raw_diffs_urls_and_unreviewed_fields_never_reach_receipt(self) -> None:
        native_records, metadata = audit_fixture()
        native = copy.deepcopy(native_records[1])
        native.update(
            {
                "objectChanges": '{"password":"SYNTHETIC_SECRET_CANARY"}',
                "applicationName": "SYNTHETIC_APPLICATION_LABEL",
                "objectId": 999,
                "ApiKeyId": "SYNTHETIC_API_KEY_ID",
                "ApiKeyName": "SYNTHETIC_API_KEY_NAME",
                "controller_url": "https://controller.example.invalid",
                "unknownNested": {"token": "SYNTHETIC_NESTED_CANARY"},
            }
        )

        receipt = adapt_appdynamics_audits([native], metadata)
        encoded = canonical_json(receipt).decode("utf-8")

        for omitted in (
            "objectChanges",
            "applicationName",
            "objectId",
            "ApiKeyId",
            "ApiKeyName",
            "controller_url",
            "unknownNested",
            "SYNTHETIC_SECRET_CANARY",
            "SYNTHETIC_APPLICATION_LABEL",
            "SYNTHETIC_API_KEY_ID",
            "SYNTHETIC_API_KEY_NAME",
            "SYNTHETIC_NESTED_CANARY",
        ):
            self.assertNotIn(omitted, encoded)

    def test_iso_time_fallback_and_unknown_time_are_not_receipt_times(self) -> None:
        native_records, metadata = audit_fixture()
        fallback = copy.deepcopy(native_records[0])
        fallback.pop("timeStamp")
        unknown = copy.deepcopy(native_records[0])
        unknown.pop("timeStamp")
        unknown.pop("auditDateTime")

        receipt = adapt_appdynamics_audits([fallback, unknown], metadata)

        fallback_object = next(
            obj for obj in receipt["objects"] if obj["event_at"] is not None
        )
        self.assertEqual(fallback_object["event_at"], 1793102400.25)
        self.assertEqual(fallback_object["actor"], "synthetic-user-01")
        self.assertEqual(fallback_object["observed_at"], 1793102402)
        self.assertIsNone(fallback_object["effective_at"])

        # Different event identities must remain distinguishable in this test;
        # a record with no native time is represented explicitly as unknown.
        unknown_object = next(
            obj for obj in receipt["objects"] if obj["event_at"] is None
        )
        self.assertEqual(unknown_object["actor"], "synthetic-user-01")
        self.assertEqual(unknown_object["observed_at"], 1793102402)

    def test_conflicting_native_times_are_rejected(self) -> None:
        native_records, metadata = audit_fixture()
        native = copy.deepcopy(native_records[0])
        native["auditDateTime"] = "2026-10-27T12:00:01.250+0000"

        with self.assertRaises(ContractError) as caught:
            adapt_appdynamics_audits([native], metadata)
        self.assertEqual(caught.exception.code, "conflicting_native_time")

    def test_bad_native_time_shapes_are_rejected(self) -> None:
        native_records, metadata = audit_fixture()
        for invalid in (True, "1793102400250", -1, 253402300800000):
            with self.subTest(invalid=invalid):
                native = copy.deepcopy(native_records[0])
                native["timeStamp"] = invalid
                with self.assertRaises(ContractError):
                    adapt_appdynamics_audits([native], metadata)

    def test_exact_projected_duplicates_collapse_and_ignore_unknown_diffs(self) -> None:
        native_records, metadata = audit_fixture()
        first = copy.deepcopy(native_records[1])
        duplicate = copy.deepcopy(first)
        duplicate["objectId"] = 27
        duplicate["objectChanges"] = "a different discarded synthetic diff"
        forward = adapt_appdynamics_audits([first, duplicate], metadata)
        reverse = adapt_appdynamics_audits([duplicate, first], metadata)

        self.assertEqual(len(forward["objects"]), 1)
        self.assertEqual(forward["objects"], reverse["objects"])

    def test_projected_identity_collision_fails_closed(self) -> None:
        native_records, metadata = audit_fixture()
        first = copy.deepcopy(native_records[0])
        second = copy.deepcopy(first)
        second["action"] = "LOGOUT"

        with patch(
            "tools.change_correlation.adapters.appdynamics.sha256_hex",
            return_value="a" * 64,
        ):
            with self.assertRaises(ContractError) as caught:
                adapt_appdynamics_audits([first, second], metadata)
        self.assertEqual(caught.exception.code, "native_identity_collision")

    def test_native_fields_are_type_checked_and_metadata_is_incremental_only(
        self,
    ) -> None:
        native_records, metadata = audit_fixture()
        native = copy.deepcopy(native_records[0])
        native["userName"] = {"name": "unexpected"}
        with self.assertRaises(ContractError) as caught:
            adapt_appdynamics_audits([native], metadata)
        self.assertEqual(caught.exception.code, "invalid_native_field")

        native_records, metadata = audit_fixture()
        metadata["deletions_authoritative"] = True
        with self.assertRaises(ContractError) as caught:
            adapt_appdynamics_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "invalid_deletion_authority")

        metadata["deletions_authoritative"] = False
        metadata["enumeration"] = "full"
        with self.assertRaises(ContractError) as caught:
            adapt_appdynamics_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "invalid_enumeration")

    def test_audit_history_produces_observations_not_configuration_diffs(self) -> None:
        native_records, metadata = audit_fixture()

        generation = build_generation(
            [adapt_appdynamics_audits(native_records, metadata)]
        )

        self.assertEqual(len(generation["rows"]), 2)
        self.assertTrue(
            all(row["record_type"] == "observation" for row in generation["rows"])
        )
        self.assertTrue(
            all(row["change_type"] == "observation" for row in generation["rows"])
        )
        self.assertTrue(all(row["kind"] == "audit" for row in generation["rows"]))

    def test_every_registered_appdynamics_feature_has_a_disposition(self) -> None:
        self.assertEqual(
            set(FEATURE_DISPOSITIONS),
            {
                "appdynamics.app_agent_audit",
                "appdynamics.instrumentation_discovery",
                "appdynamics.backend_discovery_rules",
                "appdynamics.tier_node_model",
                "appdynamics.health_rule_alert",
                "appdynamics.release_deployment",
                "appdynamics.performance_call_coverage",
                "appdynamics.controller_stable_ids",
            },
        )
        self.assertTrue(all(FEATURE_DISPOSITIONS.values()))


if __name__ == "__main__":
    unittest.main()
