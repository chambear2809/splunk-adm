"""Offline source-shape and privacy tests for ThousandEyes activity adapters."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.change_correlation.adapters.thousandeyes import (
    FEATURE_DISPOSITIONS,
    adapt_thousandeyes_activity_events,
    adapt_thousandeyes_otel_activity,
    refuse_thousandeyes_test_configuration,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE_DIR = (
    Path(__file__).parents[1] / "fixtures" / "change-correlation" / "thousandeyes"
)


def api_fixture() -> tuple[list[dict], dict]:
    value = json.loads(
        (FIXTURE_DIR / "activity_api_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )
    return value["native_records"], value["collection_metadata"]


def otel_fixture() -> tuple[dict, dict]:
    value = json.loads(
        (FIXTURE_DIR / "otel_activity_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )
    return value["native_payload"], value["collection_metadata"]


class ThousandEyesActivityApiTests(unittest.TestCase):
    def test_documented_api_rows_have_safe_context_only_projection(self) -> None:
        native_records, metadata = api_fixture()

        receipt = adapt_thousandeyes_activity_events(native_records, metadata)

        self.assertEqual(receipt["product"], "thousandeyes")
        self.assertEqual(receipt["family"], "activity_log")
        self.assertEqual(receipt["authority"], "te-org-synthetic-01")
        self.assertEqual(receipt["partition"], "aid-synthetic-01")
        self.assertEqual(receipt["enumeration"], "incremental")
        self.assertFalse(receipt["deletions_authoritative"])
        self.assertIn(
            "window_start=2026-10-27T11:59:59Z;window_end=2026-10-27T12:01:00Z",
            receipt["source_reference"],
        )
        self.assertEqual(len(receipt["objects"]), 1)

        activity = receipt["objects"][0]
        self.assertEqual(activity["event_at"], 1793102400.125)
        self.assertEqual(activity["actor"], "uid:user-synthetic-01")
        self.assertIsNone(activity["effective_at"])
        self.assertEqual(
            activity["fields"],
            {
                "account_id": "aid-synthetic-01",
                "event_name": "Test updated.",
                "resource_name": "Synthetic Checkout Probe",
                "resource_type": "testName",
            },
        )
        self.assertEqual(len(activity["object_id"]), 64)

    def test_user_ip_account_name_and_unreviewed_fields_are_dropped(self) -> None:
        native_records, metadata = api_fixture()
        native = copy.deepcopy(native_records[0])
        native.update(
            {
                "internalId": "SYNTHETIC_EVENT_ID",
                "user": "Sensitive Synthetic User (sensitive@example.invalid)",
                "ipAddress": "203.0.113.9",
                "accountGroupName": "SYNTHETIC_ACCOUNT_LABEL",
                "details": {"password": "SYNTHETIC_SECRET_CANARY"},
            }
        )

        encoded = canonical_json(
            adapt_thousandeyes_activity_events([native], metadata)
        ).decode("utf-8")

        for omitted in (
            "internalId",
            "sensitive@example.invalid",
            "Sensitive Synthetic User",
            "203.0.113.9",
            "SYNTHETIC_ACCOUNT_LABEL",
            "details",
            "SYNTHETIC_SECRET_CANARY",
        ):
            self.assertNotIn(omitted, encoded)

    def test_exact_projected_duplicates_collapse_and_replay_stably(self) -> None:
        native_records, metadata = api_fixture()
        duplicate = copy.deepcopy(native_records[0])
        duplicate["user"] = "Another ignored name (another@example.invalid)"
        duplicate["ipAddress"] = "203.0.113.10"

        forward = adapt_thousandeyes_activity_events(
            [native_records[0], duplicate], metadata
        )
        reverse = adapt_thousandeyes_activity_events(
            [duplicate, native_records[0]], metadata
        )

        self.assertEqual(len(forward["objects"]), 1)
        self.assertEqual(forward["objects"], reverse["objects"])

    def test_authority_and_partition_whitespace_is_normalized_before_identity(
        self,
    ) -> None:
        native_records, metadata = api_fixture()
        padded = {
            **metadata,
            "authority": "  te-org-synthetic-01  ",
            "partition": " aid-synthetic-01 ",
        }

        normalized = adapt_thousandeyes_activity_events(native_records, metadata)
        replay = adapt_thousandeyes_activity_events(native_records, padded)

        self.assertEqual(replay["objects"], normalized["objects"])

    def test_iso_query_start_bounds_at_datetime_limits_are_structured_errors(
        self,
    ) -> None:
        native_records, metadata = api_fixture()
        for start in ("0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00"):
            with self.subTest(start=start):
                bounded = {
                    **metadata,
                    "query_start": start,
                    "query_end": "2026-10-27T12:01:00Z",
                }
                with self.assertRaises(ContractError):
                    adapt_thousandeyes_activity_events(native_records, bounded)

    def test_iso_query_end_bounds_at_datetime_limits_are_structured_errors(
        self,
    ) -> None:
        native_records, metadata = api_fixture()
        for end in ("0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00"):
            with self.subTest(end=end):
                bounded = {
                    **metadata,
                    "query_start": "2026-10-27T11:59:59Z",
                    "query_end": end,
                }
                with self.assertRaises(ContractError):
                    adapt_thousandeyes_activity_events(native_records, bounded)

    def test_iso_activity_date_bounds_are_structured_errors(self) -> None:
        native_records, metadata = api_fixture()
        for date in ("0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00"):
            with self.subTest(date=date):
                native = copy.deepcopy(native_records[0])
                native["date"] = date
                with self.assertRaises(ContractError):
                    adapt_thousandeyes_activity_events([native], metadata)

    def test_wrong_account_group_partition_is_rejected(self) -> None:
        native_records, metadata = api_fixture()
        native_records[0]["aid"] = "different-aid"

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_activity_events(native_records, metadata)
        self.assertEqual(caught.exception.code, "wrong_native_partition")

    def test_multiple_resources_fail_closed_for_scalar_projection(self) -> None:
        native_records, metadata = api_fixture()
        native_records[0]["resources"].append(
            {"type": "testName", "name": "Another Synthetic Probe"}
        )

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_activity_events(native_records, metadata)
        self.assertEqual(caught.exception.code, "unsupported_resource_cardinality")

    def test_incomplete_api_page_receipt_is_retained_as_partial(self) -> None:
        native_records, metadata = api_fixture()
        metadata.update(
            status="partial",
            pages_expected=2,
            pages_received=1,
            permissions_fingerprint=None,
        )

        receipt = adapt_thousandeyes_activity_events(native_records, metadata)

        self.assertEqual(receipt["status"], "partial")
        self.assertEqual(receipt["pages_expected"], 2)
        self.assertEqual(receipt["pages_received"], 1)
        self.assertEqual(len(receipt["objects"]), 1)

    def test_native_timestamp_must_fit_contract_precision(self) -> None:
        native_records, metadata = api_fixture()
        native_records[0]["date"] = "2026-10-27T12:00:00.000001Z"

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_activity_events(native_records, metadata)
        self.assertEqual(caught.exception.code, "invalid_time_precision")

    def test_complete_api_receipt_requires_explicit_query_window(self) -> None:
        native_records, metadata = api_fixture()
        metadata.pop("query_start")
        metadata.pop("query_end")

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_activity_events(native_records, metadata)
        self.assertEqual(caught.exception.code, "missing_collection_window")

    def test_audit_history_is_an_observation_without_effective_time(self) -> None:
        native_records, metadata = api_fixture()

        generation = build_generation(
            [adapt_thousandeyes_activity_events(native_records, metadata)]
        )

        self.assertEqual(len(generation["rows"]), 1)
        row = generation["rows"][0]
        self.assertEqual(row["record_type"], "observation")
        self.assertEqual(row["change_type"], "observation")
        self.assertEqual(row["kind"], "audit")
        self.assertIsNone(row["effective_at"])
        self.assertTrue(row["context_only"])


class ThousandEyesOtelActivityTests(unittest.TestCase):
    def test_authority_and_partition_whitespace_is_normalized_before_identity(
        self,
    ) -> None:
        payload, metadata = otel_fixture()
        padded = {
            **metadata,
            "authority": "  te-org-synthetic-01  ",
            "partition": " stream:stream-synthetic-01 ",
        }

        normalized = adapt_thousandeyes_otel_activity(payload, metadata)
        replay = adapt_thousandeyes_otel_activity(payload, padded)

        self.assertEqual(replay["objects"], normalized["objects"])

    def test_conflicting_empty_otel_attributes_fail_in_both_orders(self) -> None:
        payload, metadata = otel_fixture()
        attributes = payload["resourceLogs"][0]["resource"]["attributes"]
        stream = next(
            item for item in attributes if item["key"] == "thousandeyes.stream.id"
        )
        empty = {"key": stream["key"], "value": {"stringValue": ""}}
        for duplicate_pair in ((stream, empty), (empty, stream)):
            with self.subTest(duplicate_pair=duplicate_pair):
                candidate = copy.deepcopy(payload)
                current = candidate["resourceLogs"][0]["resource"]["attributes"]
                index = next(
                    i for i, item in enumerate(current) if item["key"] == stream["key"]
                )
                current[index : index + 1] = list(duplicate_pair)
                with self.assertRaises(ContractError) as caught:
                    adapt_thousandeyes_otel_activity(candidate, metadata)
                self.assertEqual(caught.exception.code, "conflicting_native_field")

    def test_official_v2_log_shape_stays_separate_and_partial(self) -> None:
        payload, metadata = otel_fixture()

        receipt = adapt_thousandeyes_otel_activity(payload, metadata)

        self.assertEqual(receipt["family"], "activity_log")
        self.assertEqual(receipt["partition"], "stream:stream-synthetic-01")
        self.assertEqual(receipt["status"], "partial")
        self.assertEqual(receipt["pages_expected"], 0)
        self.assertEqual(receipt["pages_received"], 0)
        self.assertEqual(receipt["objects"][0]["event_at"], 1793102400)
        self.assertEqual(receipt["objects"][0]["observed_at"], 1793102402)
        self.assertEqual(receipt["objects"][0]["actor"], "user_id:user-synthetic-01")
        self.assertEqual(
            receipt["objects"][0]["fields"],
            {"account_id": "account-synthetic-01", "event_name": "Login"},
        )
        self.assertNotIn("resource_type", receipt["objects"][0]["fields"])
        self.assertNotIn("resource_name", receipt["objects"][0]["fields"])

    def test_sensitive_attributes_and_unparsed_resources_are_dropped(self) -> None:
        payload, metadata = otel_fixture()

        encoded = canonical_json(
            adapt_thousandeyes_otel_activity(payload, metadata)
        ).decode("utf-8")

        for omitted in (
            "thousandeyes.user.name",
            "thousandeyes.user.address",
            "thousandeyes.user.email",
            "synthetic@example.invalid",
            "192.0.2.21",
            "name:synthetic-user",
            "Synthetic Account",
        ):
            self.assertNotIn(omitted, encoded)

    def test_otel_stream_cannot_claim_complete_delivery(self) -> None:
        payload, metadata = otel_fixture()
        metadata["status"] = "complete"

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_otel_activity(payload, metadata)
        self.assertEqual(caught.exception.code, "unqualified_completeness")

    def test_otel_account_id_is_not_an_account_group_crosswalk(self) -> None:
        payload, metadata = otel_fixture()
        metadata["partition"] = "account-synthetic-01"

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_otel_activity(payload, metadata)
        self.assertEqual(caught.exception.code, "wrong_native_partition")

    def test_otel_time_beyond_millisecond_precision_is_rejected(self) -> None:
        payload, metadata = otel_fixture()
        record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        record["timeUnixNano"] = "1793102400000000001"

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_otel_activity(payload, metadata)
        self.assertEqual(caught.exception.code, "invalid_time_precision")

    def test_mixed_streams_are_rejected(self) -> None:
        payload, metadata = otel_fixture()
        second = copy.deepcopy(payload["resourceLogs"][0])
        second["resource"]["attributes"][1]["value"]["stringValue"] = (
            "stream-synthetic-02"
        )
        payload["resourceLogs"].append(second)

        with self.assertRaises(ContractError) as caught:
            adapt_thousandeyes_otel_activity(payload, metadata)
        self.assertEqual(caught.exception.code, "mixed_native_partition")


class ThousandEyesUnsupportedConfigurationTests(unittest.TestCase):
    def test_test_configuration_has_no_frozen_native_projection(self) -> None:
        with self.assertRaises(ContractError) as caught:
            refuse_thousandeyes_test_configuration([], {})
        self.assertEqual(caught.exception.code, "unsupported_projection")

    def test_every_w10_feature_has_a_disposition(self) -> None:
        self.assertEqual(
            set(FEATURE_DISPOSITIONS),
            {
                "thousandeyes.test_crud",
                "thousandeyes.target_interval",
                "thousandeyes.agent_assignment",
                "thousandeyes.alert_rule",
                "thousandeyes.stream_configuration",
                "thousandeyes.account_resource_mapping",
                "thousandeyes.metric_units_config",
                "thousandeyes.path_events",
                "thousandeyes.cea_endpoint_identity",
                "thousandeyes.api_trace_support",
            },
        )
        self.assertTrue(all(FEATURE_DISPOSITIONS.values()))


if __name__ == "__main__":
    unittest.main()
