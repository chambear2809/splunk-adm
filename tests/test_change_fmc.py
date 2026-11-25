"""FMC native-schema refusal and normalized contract export tests."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools.change_correlation.adapters.fmc import (
    adapt_fmc_access_rules,
    adapt_fmc_audits,
    adapt_fmc_deployment_jobs,
    adapt_fmc_policy_details,
    normalize_fmc_audit_export,
    render_fmc_audit_normalized_export,
)
from tools.change_correlation.contracts import ContractError, parse_json_document
from tools.change_correlation.export import (
    CHANGE_SOURCETYPE,
    EVIDENCE_SOURCETYPE,
    MANIFEST_SOURCETYPE,
)

FIXTURE_PATH = (
    Path(__file__).parents[1]
    / "fixtures"
    / "change-correlation"
    / "fmc"
    / "normalized_audit_contract_v1.json"
)


def normalized_fixture_collection() -> dict:
    collections = parse_json_document(FIXTURE_PATH.read_bytes())
    if len(collections) != 1:
        raise AssertionError("Expected one normalized contract fixture collection.")
    return collections[0]


class FmcNativeSchemaTests(unittest.TestCase):
    def test_unqualified_native_payloads_fail_closed_without_echoing_values(
        self,
    ) -> None:
        marker = "opaque-native-marker"
        adapters = (
            ("TA policy detail", adapt_fmc_policy_details),
            ("audit", adapt_fmc_audits),
            ("access rule", adapt_fmc_access_rules),
            ("deployment", adapt_fmc_deployment_jobs),
        )
        for family, adapter in adapters:
            with self.subTest(family=family):
                with self.assertRaises(ContractError) as raised:
                    adapter(
                        [{"unqualifiedField": marker}],
                        {"source_version": "7.7.0", "ta_version": "3.7.2"},
                    )

                self.assertEqual(raised.exception.code, "unsupported_source_schema")
                self.assertNotIn(marker, str(raised.exception))
                self.assertNotIn("unqualifiedField", str(raised.exception))

    def test_version_metadata_alone_cannot_enable_native_mapping(self) -> None:
        with self.assertRaises(ContractError) as raised:
            adapt_fmc_policy_details(
                [],
                {
                    "source_version": "7.7.0",
                    "ta_version": "3.7.2",
                    "schema_version": "unknown",
                },
            )

        self.assertEqual(raised.exception.code, "unsupported_source_schema")


class FmcNormalizedExportTests(unittest.TestCase):
    def test_normalized_contract_collection_uses_frozen_projection(self) -> None:
        normalized = normalize_fmc_audit_export(normalized_fixture_collection())

        self.assertEqual(normalized["product"], "fmc")
        self.assertEqual(normalized["family"], "audit_record")
        self.assertEqual(
            normalized["objects"][0]["fields"],
            {
                "action": "modified",
                "domain_id": "domain-contract-fixture",
                "source": "api",
                "subsystem": "access_policy",
            },
        )

    def test_normalized_contract_is_exported_with_unqualified_source_status(
        self,
    ) -> None:
        normalized = normalized_fixture_collection()
        first = render_fmc_audit_normalized_export(normalized, index="atlas_changes")
        second = render_fmc_audit_normalized_export(normalized, index="atlas_changes")
        self.assertEqual(first, second)

        events = [json.loads(line) for line in first.splitlines()]
        self.assertEqual(
            {event["sourcetype"] for event in events},
            {EVIDENCE_SOURCETYPE, CHANGE_SOURCETYPE, MANIFEST_SOURCETYPE},
        )
        self.assertEqual({event["index"] for event in events}, {"atlas_changes"})

        receipt = next(
            event["event"]
            for event in events
            if event["sourcetype"] == EVIDENCE_SOURCETYPE
            and event["event"]["record_type"] == "receipt"
        )
        observation = next(
            event["event"]
            for event in events
            if event["sourcetype"] == EVIDENCE_SOURCETYPE
            and event["event"]["record_type"] == "object_observation"
        )
        change_row = next(
            event["event"]
            for event in events
            if event["sourcetype"] == CHANGE_SOURCETYPE
        )

        self.assertEqual(receipt["projection_qualification"], "normalized_export_only")
        self.assertTrue(receipt["native_sample_unqualified"])
        self.assertEqual(
            observation["projection_qualification"], "normalized_export_only"
        )
        self.assertTrue(observation["native_sample_unqualified"])
        self.assertEqual(change_row["attributes"]["action"], "modified")
        self.assertEqual(
            change_row["projection_qualification"], "normalized_export_only"
        )
        self.assertTrue(change_row["native_sample_unqualified"])

    def test_normalized_path_rejects_other_products_and_families(self) -> None:
        collection = normalized_fixture_collection()
        collection["product"] = "ftd"
        with self.assertRaises(ContractError) as raised:
            normalize_fmc_audit_export(collection)
        self.assertEqual(raised.exception.code, "unsupported_projection")


if __name__ == "__main__":
    unittest.main()
