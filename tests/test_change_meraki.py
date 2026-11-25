"""Offline source-shape and privacy tests for the Meraki adapters."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.change_correlation.adapters.meraki import (
    adapt_meraki_audits,
    adapt_meraki_ssid_snapshots,
)
from tools.change_correlation.contracts import ContractError, canonical_json
from tools.change_correlation.history import build_generation

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "change-correlation" / "meraki"


def audit_fixture() -> tuple[list[dict], dict]:
    value = json.loads(
        (FIXTURE_DIR / "configuration_changes_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )
    return value["native_records"], value["collection_metadata"]


def ssid_fixture() -> tuple[list[dict], dict]:
    value = json.loads(
        (FIXTURE_DIR / "ssid_snapshot_documentation_shaped.json").read_text(
            encoding="utf-8"
        )
    )
    return value["native_records"], value["collection_metadata"]


class MerakiAuditAdapterTests(unittest.TestCase):
    def test_documentation_shaped_audit_rows_have_safe_typed_projection(self) -> None:
        native_records, metadata = audit_fixture()

        receipt = adapt_meraki_audits(native_records, metadata)

        self.assertEqual(receipt["product"], "meraki")
        self.assertEqual(receipt["family"], "configuration_change")
        self.assertEqual(receipt["authority"], "org-synthetic")
        self.assertEqual(receipt["partition"], "org-synthetic")
        self.assertEqual(receipt["scope"], "change-a")
        self.assertFalse(receipt["deletions_authoritative"])
        self.assertEqual(len(receipt["objects"]), 2)
        by_network = {
            obj["fields"].get("network_id"): obj for obj in receipt["objects"]
        }
        scoped = by_network["network-synthetic-01"]
        self.assertEqual(scoped["event_at"], 1793102400.25)
        self.assertEqual(scoped["actor"], "admin-synthetic-01")
        self.assertEqual(
            scoped["fields"],
            {
                "client_type": "oauth",
                "label": "Updated a wireless SSID setting",
                "network_id": "network-synthetic-01",
                "page": "Wireless > SSIDs",
                "ssid_number": 0,
            },
        )
        unscoped = by_network[None]
        self.assertIsNone(unscoped["actor"])
        self.assertNotIn("ssid_number", unscoped["fields"])
        self.assertEqual(len(scoped["object_id"]), 64)

    def test_raw_config_personal_fields_and_urls_never_reach_the_receipt(self) -> None:
        native_records, metadata = audit_fixture()
        native = copy.deepcopy(native_records[0])
        native.update(
            {
                "oldValue": '{"password":"SYNTHETIC_SECRET_CANARY"}',
                "newValue": '{"token":"SYNTHETIC_TOKEN_CANARY"}',
                "adminName": "SYNTHETIC_ADMIN_NAME",
                "adminEmail": "SYNTHETIC_EMAIL@example.invalid",
                "networkName": "SYNTHETIC_NETWORK_NAME",
                "networkUrl": "https://example.invalid/network/SYNTHETIC_URL",
                "ssidName": "SYNTHETIC_SSID_NAME",
                "client": {
                    "id": "SYNTHETIC_CLIENT_ID",
                    "type": "oauth",
                },
                "unknownNested": {"secret": "SYNTHETIC_NESTED_CANARY"},
            }
        )

        receipt = adapt_meraki_audits([native], metadata)
        encoded = canonical_json(receipt).decode("utf-8")

        for omitted in (
            "oldValue",
            "newValue",
            "adminName",
            "adminEmail",
            "networkName",
            "networkUrl",
            "ssidName",
            "client.id",
            "SYNTHETIC_SECRET_CANARY",
            "SYNTHETIC_TOKEN_CANARY",
            "SYNTHETIC_ADMIN_NAME",
            "SYNTHETIC_EMAIL",
            "SYNTHETIC_NETWORK_NAME",
            "SYNTHETIC_URL",
            "SYNTHETIC_SSID_NAME",
            "SYNTHETIC_CLIENT_ID",
            "SYNTHETIC_NESTED_CANARY",
        ):
            self.assertNotIn(omitted, encoded)

    def test_exact_safe_duplicates_collapse_and_native_order_is_irrelevant(
        self,
    ) -> None:
        native_records, metadata = audit_fixture()
        first = copy.deepcopy(native_records[0])
        duplicate = copy.deepcopy(first)
        duplicate["oldValue"] = "different excluded old value"
        duplicate["newValue"] = "different excluded new value"
        duplicate["adminEmail"] = "another@example.invalid"
        duplicate["client"]["id"] = "another excluded client id"

        forward = adapt_meraki_audits([first, duplicate], metadata)
        reverse = adapt_meraki_audits([duplicate, first], metadata)

        self.assertEqual(len(forward["objects"]), 1)
        self.assertEqual(forward["objects"], reverse["objects"])

    def test_native_organization_mismatch_is_rejected(self) -> None:
        native_records, metadata = audit_fixture()
        native_records[0]["organizationId"] = "different-organization"

        with self.assertRaises(ContractError) as caught:
            adapt_meraki_audits(native_records, metadata)
        self.assertEqual(caught.exception.code, "wrong_authority")

    def test_single_network_audit_partition_is_checked_without_using_scope(
        self,
    ) -> None:
        native_records, metadata = audit_fixture()
        metadata["partition"] = "network:network-synthetic-01"
        metadata["scope"] = "change-b"

        receipt = adapt_meraki_audits([native_records[0]], metadata)

        self.assertEqual(receipt["partition"], "network:network-synthetic-01")
        self.assertEqual(receipt["scope"], "change-b")
        native_records[0]["networkId"] = "another-network"
        with self.assertRaises(ContractError) as caught:
            adapt_meraki_audits([native_records[0]], metadata)
        self.assertEqual(caught.exception.code, "wrong_network_partition")

    def test_ssid_number_without_network_id_is_not_projected(self) -> None:
        native_records, metadata = audit_fixture()
        native = copy.deepcopy(native_records[0])
        native["networkId"] = None
        native["ssidNumber"] = 0

        receipt = adapt_meraki_audits([native], metadata)

        fields = receipt["objects"][0]["fields"]
        self.assertNotIn("network_id", fields)
        self.assertNotIn("ssid_number", fields)

    def test_different_safe_content_cannot_reuse_an_audit_identity(self) -> None:
        native_records, metadata = audit_fixture()
        first = copy.deepcopy(native_records[0])
        second = copy.deepcopy(first)
        second["label"] = "A different reviewed label"

        with patch(
            "tools.change_correlation.adapters.meraki.sha256_hex",
            return_value="a" * 64,
        ):
            with self.assertRaises(ContractError) as caught:
                adapt_meraki_audits([first, second], metadata)
        self.assertEqual(caught.exception.code, "native_identity_collision")

    def test_audit_rows_remain_context_only_observations(self) -> None:
        native_records, metadata = audit_fixture()

        generation = build_generation([adapt_meraki_audits(native_records, metadata)])

        observations = [
            row for row in generation["rows"] if row["record_type"] == "observation"
        ]
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(row["context_only"] for row in observations))
        self.assertTrue(
            all(row["change_type"] == "observation" for row in observations)
        )


class MerakiSsidSnapshotAdapterTests(unittest.TestCase):
    def test_documented_ssid_response_is_allowlisted_and_network_qualified(
        self,
    ) -> None:
        native_records, metadata = ssid_fixture()
        native = copy.deepcopy(native_records[0])
        native.update(
            {
                "psk": "SYNTHETIC_SECRET_CANARY",
                "radiusServers": [{"host": "SYNTHETIC_RADIUS_HOST"}],
                "networkName": "SYNTHETIC_NETWORK_NAME",
                "networkUrl": "https://example.invalid/SYNTHETIC_URL",
                "unknownNested": {"secret": "SYNTHETIC_NESTED_CANARY"},
            }
        )

        receipt = adapt_meraki_ssid_snapshots([native], metadata)

        self.assertEqual(receipt["family"], "ssid_snapshot")
        self.assertEqual(receipt["authority"], "org-synthetic")
        self.assertEqual(receipt["partition"], "network:network-synthetic-01")
        self.assertEqual(receipt["scope"], "change-a")
        self.assertEqual(
            receipt["objects"][0]["fields"],
            {
                "auth_mode": "open",
                "default_vlan_id": 71,
                "enabled": True,
                "ip_assignment_mode": "Bridge mode",
                "network_id": "network-synthetic-01",
                "ssid_name": "Synthetic Guest",
                "ssid_number": 0,
                "use_vlan_tagging": True,
            },
        )
        self.assertEqual(
            receipt["objects"][0]["object_id"],
            "org:org-synthetic/network:network-synthetic-01/ssid:0",
        )
        encoded = canonical_json(receipt).decode("utf-8")
        for omitted in (
            "psk",
            "radiusServers",
            "networkName",
            "networkUrl",
            "SYNTHETIC_SECRET_CANARY",
            "SYNTHETIC_RADIUS_HOST",
            "SYNTHETIC_NETWORK_NAME",
            "SYNTHETIC_URL",
            "SYNTHETIC_NESTED_CANARY",
        ):
            self.assertNotIn(omitted, encoded)

    def test_optional_vlan_fields_may_be_absent(self) -> None:
        native_records, metadata = ssid_fixture()
        native = copy.deepcopy(native_records[0])
        native.pop("defaultVlanId")
        native.pop("useVlanTagging")

        receipt = adapt_meraki_ssid_snapshots([native], metadata)

        self.assertNotIn("default_vlan_id", receipt["objects"][0]["fields"])
        self.assertNotIn("use_vlan_tagging", receipt["objects"][0]["fields"])

    def test_default_vlan_requires_documented_vlan_tagging_semantics(self) -> None:
        native_records, metadata = ssid_fixture()
        native = copy.deepcopy(native_records[0])
        native["useVlanTagging"] = False

        with self.assertRaises(ContractError) as caught:
            adapt_meraki_ssid_snapshots([native], metadata)
        self.assertEqual(caught.exception.code, "invalid_vlan_semantics")

        native.pop("defaultVlanId")
        native["ipAssignmentMode"] = "NAT mode"
        with self.assertRaises(ContractError) as caught:
            adapt_meraki_ssid_snapshots([native], metadata)
        self.assertEqual(caught.exception.code, "invalid_vlan_semantics")

    def test_network_scope_and_native_scalar_types_are_strict(self) -> None:
        native_records, metadata = ssid_fixture()
        native = copy.deepcopy(native_records[0])
        native["networkId"] = "different-network"
        with self.assertRaises(ContractError) as caught:
            adapt_meraki_ssid_snapshots([native], metadata)
        self.assertEqual(caught.exception.code, "wrong_network_partition")

        native.pop("networkId")
        native["enabled"] = "true"
        with self.assertRaises(ContractError) as caught:
            adapt_meraki_ssid_snapshots([native], metadata)
        self.assertEqual(caught.exception.code, "invalid_native_field")

        native["enabled"] = True
        bad_partition = copy.deepcopy(metadata)
        bad_partition["partition"] = "network:"
        with self.assertRaises(ContractError) as caught:
            adapt_meraki_ssid_snapshots([native], bad_partition)
        self.assertEqual(caught.exception.code, "invalid_native_partition")

    def test_same_ssid_number_in_another_organization_stays_distinct(self) -> None:
        native_records, metadata = ssid_fixture()
        first = adapt_meraki_ssid_snapshots(native_records, metadata)

        other_metadata = copy.deepcopy(metadata)
        other_metadata.update(
            {
                "capture_id": "meraki-ssid-other-org-001",
                "authority": "org-other-synthetic",
                "partition": "network:network-synthetic-01",
                "scope": "change-b",
            }
        )
        other = adapt_meraki_ssid_snapshots(native_records, other_metadata)

        self.assertEqual(first["objects"][0]["fields"]["ssid_number"], 0)
        self.assertEqual(other["objects"][0]["fields"]["ssid_number"], 0)
        self.assertNotEqual(
            first["objects"][0]["object_id"], other["objects"][0]["object_id"]
        )
        self.assertEqual(other["authority"], "org-other-synthetic")
        self.assertEqual(other["partition"], "network:network-synthetic-01")
        self.assertEqual(other["scope"], "change-b")

    def test_conflicting_duplicate_ssid_identity_fails_closed(self) -> None:
        native_records, metadata = ssid_fixture()
        changed = copy.deepcopy(native_records[0])
        changed["defaultVlanId"] = 72

        with self.assertRaises(ContractError) as caught:
            adapt_meraki_ssid_snapshots([native_records[0], changed], metadata)
        self.assertEqual(caught.exception.code, "native_identity_collision")

    def test_snapshot_vlan_change_is_an_interval_not_an_effective_instant(self) -> None:
        native_records, metadata = ssid_fixture()
        before = adapt_meraki_ssid_snapshots(native_records, metadata)

        changed_metadata = copy.deepcopy(metadata)
        changed_metadata.update(
            {
                "capture_id": "meraki-ssid-doc-fixture-002",
                "started_at": 1_793_102_880,
                "completed_at": 1_793_102_890,
                "received_at": 1_793_102_891,
            }
        )
        changed_record = copy.deepcopy(native_records[0])
        changed_record["defaultVlanId"] = 72
        after = adapt_meraki_ssid_snapshots([changed_record], changed_metadata)

        generation = build_generation([before, after])
        change = next(
            row for row in generation["rows"] if row["record_type"] == "change"
        )

        self.assertEqual(change["change_type"], "modified")
        self.assertEqual(change["earliest_at"], metadata["started_at"])
        self.assertEqual(change["latest_at"], changed_metadata["completed_at"])
        self.assertIsNone(change["event_at"])
        self.assertIsNone(change["effective_at"])
        self.assertEqual(
            [
                diff
                for diff in change["field_diffs"]
                if diff["field"] == "default_vlan_id"
            ],
            [
                {
                    "field": "default_vlan_id",
                    "before": 71,
                    "after": 72,
                    "before_present": True,
                    "after_present": True,
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
