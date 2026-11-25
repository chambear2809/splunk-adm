"""Bounded FTD eStreamer connection observation adapter tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from tools.change_correlation.adapters.ftd import adapt_ftd_connection_records
from tools.change_correlation.contracts import ContractError
from tools.change_correlation.history import build_generation
from tools.change_correlation.projections import projection_for

FIXTURE_PATH = (
    Path(__file__).parents[1]
    / "fixtures"
    / "change-correlation"
    / "ftd"
    / "connection_event_fqe74_doc_shaped_synthetic.json"
)
_MISSING = object()


def fixture_document() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


def fixture_metadata() -> dict:
    return copy.deepcopy(fixture_document()["collection_metadata"])


def native_connection(**overrides: object) -> dict:
    event = {
        "EventType": "ConnectionEvent",
        "SourceHost": "fmc-synthetic.example.invalid",
        "DeviceIP": "192.0.2.10",
        "DeviceUUID": "550e8400-e29b-41d4-a716-446655440000",
        "DeviceSerialNumber": "FTD-SYNTHETIC-001",
        "InstanceID": 2,
        "ConnectionID": 101,
        "FirstPacketSecond": 1_791_373_808,
        "EventSecond": 1_791_373_810,
        "InitiatorIP": "198.51.100.8",
        "InitiatorPort": 51400,
        "ResponderIP": "203.0.113.10",
        "ResponderPort": 443,
        "Protocol": "TCP",
        "AC_RuleAction": "Block",
        "FirewallPolicy": "Synthetic Edge Policy",
        "FirewallRule": "Synthetic Access Rule",
    }
    event.update(overrides)
    return event


def source_record(
    *,
    fingerprint_number: int = 1,
    indexed_at: int | float = 1_791_373_812,
    event: dict | None = None,
) -> dict:
    return {
        "event_fingerprint": f"{fingerprint_number:064x}",
        "_indextime": indexed_at,
        "native_event": event if event is not None else native_connection(),
    }


class FtdDocumentationShapedFixtureTests(unittest.TestCase):
    def test_fixture_is_synthetic_and_yields_operational_observations(self) -> None:
        document = fixture_document()
        self.assertIn("not a native sample", document["fixture_note"])

        collection = adapt_ftd_connection_records(
            document["records"], document["collection_metadata"]
        )

        self.assertEqual(collection["product"], "ftd")
        self.assertEqual(collection["family"], "connection_observation")
        self.assertEqual(collection["status"], "partial")
        self.assertFalse(collection["deletions_authoritative"])
        self.assertEqual(len(collection["objects"]), 4)
        self.assertEqual(
            {item["kind"] for item in collection["objects"]}, {"operational"}
        )
        self.assertTrue(
            set().union(*(item["fields"] for item in collection["objects"]))
            <= set(projection_for("ftd", "connection_observation"))
        )
        generation = build_generation([collection])
        observations = [
            item
            for item in generation["observations"]
            if item["record_type"] == "object_observation"
        ]
        self.assertEqual(len(observations), 4)
        self.assertEqual(
            {item["projection_qualification"] for item in observations},
            {"normalized_export_only"},
        )
        self.assertTrue(all(item["native_sample_unqualified"] for item in observations))


class FtdActionMappingTests(unittest.TestCase):
    def test_exact_documented_actions_have_conservative_outcomes(self) -> None:
        expected = {
            "Allow": ("Allow", "reported_allow_trust"),
            "Trust": ("Trust", "reported_allow_trust"),
            "Block": ("Block", "reported_block"),
            "Block with reset": ("Block with reset", "reported_block"),
            "Interactive Block": ("Interactive Block", "interactive_initial_block"),
            "Interactive Block with reset": (
                "Interactive Block with reset",
                "interactive_initial_block",
            ),
            "Fastpath": ("Fastpath", "fastpath"),
            "Default Action": ("Default Action", "unknown"),
        }
        records = [
            source_record(
                fingerprint_number=number,
                event=native_connection(AC_RuleAction=action),
            )
            for number, action in enumerate(expected, start=1)
        ]
        collection = adapt_ftd_connection_records(records, fixture_metadata())

        observed = {
            item["fields"]["reported_action"]: item["fields"]["outcome"]
            for item in collection["objects"]
        }
        self.assertEqual(
            observed,
            {
                reported_action: outcome
                for reported_action, outcome in expected.values()
            },
        )

    def test_missing_blank_and_unrecognized_actions_are_unknown_not_permit(
        self,
    ) -> None:
        missing = native_connection()
        missing.pop("AC_RuleAction")
        records = [
            source_record(fingerprint_number=1, event=missing),
            source_record(
                fingerprint_number=2, event=native_connection(AC_RuleAction="")
            ),
            source_record(
                fingerprint_number=3,
                event=native_connection(AC_RuleAction="Allow with reset"),
            ),
        ]

        collection = adapt_ftd_connection_records(records, fixture_metadata())

        self.assertEqual(
            [item["fields"]["outcome"] for item in collection["objects"]],
            ["unknown", "unknown", "unknown"],
        )
        self.assertEqual(
            [item["fields"]["reported_action"] for item in collection["objects"]],
            [None, None, None],
        )

    def test_multivalue_action_fails_closed(self) -> None:
        record = source_record(
            event=native_connection(AC_RuleAction=["Allow", "Block"])
        )
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([record], fixture_metadata())
        self.assertEqual(raised.exception.code, "invalid_source_field")


class FtdIdentityAndTimeTests(unittest.TestCase):
    def test_index_fingerprint_and_receipt_are_distinct_from_native_times(self) -> None:
        fingerprint = "a" * 64
        record = {
            "event_fingerprint": fingerprint,
            "_indextime": 1_791_373_812.25,
            "native_event": native_connection(
                ConnectionID=777,
                FirstPacketSecond=1_791_373_808,
                EventSecond=1_791_373_810,
            ),
        }
        metadata = fixture_metadata()
        metadata["received_at"] = 1_791_374_000

        collection = adapt_ftd_connection_records([record], metadata)
        observation = collection["objects"][0]
        fields = observation["fields"]

        self.assertEqual(observation["object_id"], fingerprint)
        self.assertEqual(fields["event_fingerprint"], fingerprint)
        self.assertEqual(
            fields["evidence_identity_basis"], "trusted_indexed_event_fingerprint"
        )
        self.assertEqual(fields["connection_id"], "777")
        self.assertEqual(observation["observed_at"], 1_791_373_812.25)
        self.assertEqual(collection["received_at"], 1_791_374_000)
        self.assertEqual(observation["event_at"], 1_791_373_810)
        self.assertEqual(fields["first_packet_at"], 1_791_373_808)
        self.assertEqual(fields["event_detected_at"], 1_791_373_810)

        generation = build_generation([collection])
        row = next(
            item for item in generation["rows"] if item["record_type"] == "observation"
        )
        self.assertEqual(row["event_at"], 1_791_373_810)
        self.assertEqual(row["time_qualification"], "source_event_time_reported")

    def test_connection_id_alone_never_deduplicates_events(self) -> None:
        records = [
            source_record(
                fingerprint_number=1,
                event=native_connection(ConnectionID=777),
            ),
            source_record(
                fingerprint_number=2,
                event=native_connection(ConnectionID=777),
            ),
        ]

        collection = adapt_ftd_connection_records(records, fixture_metadata())

        self.assertEqual(
            [item["object_id"] for item in collection["objects"]],
            [f"{1:064x}", f"{2:064x}"],
        )
        self.assertEqual(
            {item["fields"]["connection_id"] for item in collection["objects"]},
            {"777"},
        )

    def test_reported_device_identity_and_tuple_fields_are_retained(self) -> None:
        collection = adapt_ftd_connection_records(
            [source_record(event=native_connection())], fixture_metadata()
        )

        fields = collection["objects"][0]["fields"]
        self.assertEqual(fields["device_ip"], "192.0.2.10")
        self.assertEqual(fields["device_uuid"], "550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(fields["device_serial"], "FTD-SYNTHETIC-001")
        self.assertEqual(fields["instance_id"], "2")
        self.assertEqual(fields["connection_id"], "101")
        self.assertEqual(fields["protocol"], "TCP")
        self.assertEqual(fields["reported_initiator_ip"], "198.51.100.8")
        self.assertEqual(fields["reported_initiator_port"], 51400)
        self.assertEqual(fields["reported_responder_ip"], "203.0.113.10")
        self.assertEqual(fields["reported_responder_port"], 443)

    def test_event_second_is_optional_and_first_packet_is_not_substituted(self) -> None:
        event = native_connection()
        event.pop("EventSecond")
        collection = adapt_ftd_connection_records(
            [source_record(event=event)], fixture_metadata()
        )
        observation = collection["objects"][0]

        self.assertIsNone(observation["event_at"])
        self.assertEqual(observation["fields"]["first_packet_at"], 1_791_373_808)
        self.assertIsNone(observation["fields"]["event_detected_at"])


class FtdValidationTests(unittest.TestCase):
    def test_source_host_must_match_configured_fmc_authority_exactly(self) -> None:
        record = source_record(
            event=native_connection(SourceHost="other-fmc.example.invalid")
        )
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([record], fixture_metadata())
        self.assertEqual(raised.exception.code, "source_authority_mismatch")
        self.assertNotIn("other-fmc", str(raised.exception))

    def test_fingerprint_and_index_receipt_are_required_and_bounded(self) -> None:
        invalid = source_record()
        invalid["event_fingerprint"] = "ConnectionID-is-not-a-fingerprint"
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([invalid], fixture_metadata())
        self.assertEqual(raised.exception.code, "invalid_event_fingerprint")

        missing_receipt = source_record()
        missing_receipt.pop("_indextime")
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([missing_receipt], fixture_metadata())
        self.assertEqual(raised.exception.code, "invalid_source_record")

        invalid_receipt = source_record(indexed_at="not-a-time")
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([invalid_receipt], fixture_metadata())
        self.assertEqual(raised.exception.code, "invalid_source_time")

    def test_reported_tuple_requires_single_valid_ips_and_ports(self) -> None:
        valid = native_connection(
            InitiatorIP="2001:db8::8",
            InitiatorPort=0,
            ResponderIP="203.0.113.22",
            ResponderPort=65535,
        )
        collection = adapt_ftd_connection_records(
            [source_record(event=valid)], fixture_metadata()
        )
        fields = collection["objects"][0]["fields"]
        self.assertEqual(fields["reported_initiator_ip"], "2001:db8::8")
        self.assertEqual(fields["reported_initiator_port"], 0)
        self.assertEqual(fields["reported_responder_ip"], "203.0.113.22")
        self.assertEqual(fields["reported_responder_port"], 65535)

        for overrides in (
            {"InitiatorIP": "not-an-ip"},
            {"ResponderIP": ["203.0.113.22"]},
            {"InitiatorPort": 65536},
            {"ResponderPort": True},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ContractError) as raised:
                    adapt_ftd_connection_records(
                        [source_record(event=native_connection(**overrides))],
                        fixture_metadata(),
                    )
                self.assertEqual(raised.exception.code, "invalid_source_field")

    def test_optional_tuple_members_and_unreviewed_fields_do_not_expand_evidence(
        self,
    ) -> None:
        event = native_connection(
            InitiatorIP="198.51.100.4",
            ResponderIP=None,
            ResponderPort=None,
            NAT_InitiatorIP="203.0.113.99",
            InitiatorBytes=50_000,
            FirewallRuleID="unrequested-id",
            raw_payload="must not be retained",
        )
        collection = adapt_ftd_connection_records(
            [source_record(event=event)], fixture_metadata()
        )
        fields = collection["objects"][0]["fields"]

        self.assertEqual(fields["reported_initiator_ip"], "198.51.100.4")
        self.assertIsNone(fields["reported_responder_ip"])
        self.assertIsNone(fields["reported_responder_port"])
        self.assertNotIn("NAT_InitiatorIP", fields)
        self.assertNotIn("InitiatorBytes", fields)
        self.assertNotIn("FirewallRuleID", fields)
        self.assertNotIn("raw_payload", fields)

    def test_invalid_documented_fields_and_non_connection_events_fail_safely(
        self,
    ) -> None:
        for overrides in (
            {"EventType": "IntrusionEvent"},
            {"DeviceIP": "not-an-ip"},
            {"FirstPacketSecond": "1791373808"},
            {"EventSecond": [1_791_373_810]},
            {"FirewallPolicy": ["two", "names"]},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ContractError):
                    adapt_ftd_connection_records(
                        [source_record(event=native_connection(**overrides))],
                        fixture_metadata(),
                    )

    def test_metadata_cannot_change_product_or_family(self) -> None:
        metadata = fixture_metadata()
        metadata["product"] = "fmc"
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([], metadata)
        self.assertEqual(raised.exception.code, "unsupported_projection")

    def test_authority_whitespace_is_not_normalized_for_source_matching(self) -> None:
        metadata = fixture_metadata()
        metadata["authority"] = " fmc-synthetic.example.invalid"
        record = source_record(
            event=native_connection(SourceHost=" fmc-synthetic.example.invalid")
        )
        with self.assertRaises(ContractError) as raised:
            adapt_ftd_connection_records([record], metadata)
        self.assertEqual(raised.exception.code, "invalid_source_metadata")


if __name__ == "__main__":
    unittest.main()
