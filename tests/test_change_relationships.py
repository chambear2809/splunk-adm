"""Administrator relationship ingress, retained history and extraction tests."""

from __future__ import annotations

import copy
import unittest

from tools.change_correlation.contracts import ContractError, normalize_collection
from tools.change_correlation.history import build_generation
from tools.change_correlation.relationships import (
    RelationshipError,
    attribute_change,
    administrator_relationship_collections,
    captured_dependency_identity,
    extract_retained_relationships,
)


def binding(**updates):
    value = {
        "authority": "atlas:observed_dependency",
        "identity_type": "captured_dependency",
        "scenario_id": "scenario-a",
        "execution_id": "execution-a",
        "graph_result_key": "graph:phase-a",
        "graph_result_sha256": "a" * 64,
        "edge_id": "edge-a",
        "scope": "routing-scope-a",
        "window": {"earliest": 1_000, "latest": 1_060},
        "query_sha256": "b" * 64,
        "receipt_basis": "query_input_coverage_v1",
        "query_input_coverage_sha256": "f" * 64,
        "active_traffic_contract_sha256": "c" * 64,
        "receipt_fingerprints": ["d" * 64, "e" * 64],
    }
    value.update(updates)
    return value


def envelope(*, evidence_id="attestation:edge-a", link_updates=None, **updates):
    captured = binding()
    target = captured_dependency_identity(captured)
    relationship = {
        "from_authority": "controller:firewall-a",
        "from_type": "policy",
        "from_id": "policy:checkout",
        "to_authority": target["authority"],
        "to_type": target["type"],
        "to_id": target["id"],
        "scope": "routing-scope-a",
        "valid_from": 900,
        "valid_to": 1_100,
        "evidence_id": evidence_id,
        "binding": captured,
    }
    relationship.update(link_updates or {})
    value = {
        "schema_version": 1,
        "capture_id": "admin-capture-a",
        "issuer": "network-admin-team",
        "source_version": "atlas-admin-relationship-v1",
        "attestation_version": "1",
        "proof": "change-record:CHG-1234",
        "actor": "admin:alex",
        "qualification": "owned_local_lab_admin_unqualified",
        "recorded_at": 1_200,
        "source_reference": "approval:CHG-1234",
        "relationships": [relationship],
    }
    value.update(updates)
    return value


class AdministratorRelationshipIngressTests(unittest.TestCase):
    def test_https_authority_is_accepted_for_change_identity(self):
        authority = "https://controller.example"
        result = attribute_change(
            {
                "authority": authority,
                "family": "service_snapshot",
                "object_id": "service:payments",
                "scope": "prod-east",
                "earliest_at": 100,
                "latest_at": 200,
            },
            scope="prod-east",
            start=50,
            end=250,
            objects=[
                {
                    "authority": authority,
                    "type": "service_snapshot",
                    "id": "service:payments",
                }
            ],
            observed_dependencies=[],
            relationships=[],
        )
        self.assertEqual(result["attribution_class"], "direct_object")

    def test_generic_normalizer_rejects_reserved_relationship_family(self):
        raw = {
            "schema_version": 1,
            "capture_id": "vendor-forgery",
            "product": "atlas",
            "authority": "atlas:administrator_attestation",
            "source_version": "vendor-1",
            "family": "relationship_attestation",
            "partition": "p",
            "scope": "routing-scope-a",
            "started_at": 1_000,
            "completed_at": 1_010,
            "received_at": 1_011,
            "status": "complete",
            "permissions_fingerprint": "vendor-claims-admin",
            "pages_expected": 1,
            "pages_received": 1,
            "source_reference": "vendor:capture",
            "enumeration": "incremental",
            "deletions_authoritative": False,
            "objects": [],
        }
        with self.assertRaisesRegex(ContractError, "separate trusted ingress"):
            normalize_collection(raw)
        with self.assertRaisesRegex(ContractError, "separate trusted ingress"):
            build_generation([raw])

    def test_vendor_json_cannot_set_internal_administrator_ingress_flag(self):
        raw = envelope()
        raw["_administrator_ingress"] = True
        with self.assertRaises(ContractError):
            normalize_collection(raw)

    def test_admin_envelope_is_retained_inside_the_generation(self):
        generation = build_generation([], administrator_relationships=[envelope()])
        rows = generation["rows"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["record_type"], "observation")
        self.assertEqual(row["product"], "atlas")
        self.assertEqual(row["family"], "relationship_attestation")
        self.assertEqual(row["authority"], "atlas:administrator_attestation")
        self.assertTrue(row["context_only"])
        self.assertEqual(row["event_at"], None)
        self.assertEqual(row["effective_at"], None)
        self.assertEqual(row["actor"], "admin:alex")
        self.assertEqual(row["source_version"], "atlas-admin-relationship-v1")
        self.assertEqual(row["attributes"]["issuer"], "network-admin-team")
        self.assertEqual(row["attributes"]["attestation_version"], "1")
        self.assertEqual(row["attributes"]["proof"], "change-record:CHG-1234")
        self.assertEqual(
            row["attributes"]["proof_qualification"],
            "administrator_supplied_unverified",
        )
        self.assertEqual(row["attributes"]["basis"], "administrator_attestation")
        self.assertEqual(row["attributes"]["semantics"], "potential_dependency")
        self.assertEqual(
            row["attributes"]["binding_receipt_basis"],
            "query_input_coverage_v1",
        )
        self.assertEqual(
            row["attributes"]["binding_query_input_coverage_sha256"], "f" * 64
        )
        self.assertEqual(
            row["attributes"]["qualification"],
            "owned_local_lab_admin_unqualified",
        )
        self.assertEqual(len(generation["receipts"]), 1)
        self.assertEqual(len(generation["observations"]), 1)
        self.assertEqual(len(generation["manifest"]["source_receipt_hashes"]), 1)
        self.assertEqual(generation["manifest"]["row_count"], 1)

    def test_retained_extraction_returns_full_admin_proof_and_capture_binding(self):
        generation = build_generation([], administrator_relationships=[envelope()])
        extracted = extract_retained_relationships(
            generation["rows"], generation_id=generation["manifest"]["generation_id"]
        )
        self.assertTrue(extracted["complete"])
        link = extracted["relationships"][0]
        self.assertEqual(link["issuer"], "network-admin-team")
        self.assertEqual(link["source_version"], "atlas-admin-relationship-v1")
        self.assertEqual(link["attestation_version"], "1")
        self.assertEqual(link["actor"], "admin:alex")
        self.assertEqual(link["proof"], "change-record:CHG-1234")
        self.assertEqual(link["basis"], "administrator_attestation")
        self.assertEqual(link["semantics"], "potential_dependency")
        self.assertEqual(link["qualification"], "owned_local_lab_admin_unqualified")
        self.assertEqual(link["target_binding"]["edge_id"], "edge-a")
        self.assertEqual(
            link["target_binding"]["receipt_fingerprints"], ["d" * 64, "e" * 64]
        )
        self.assertEqual(
            link["target_binding"]["receipt_basis"], "query_input_coverage_v1"
        )
        self.assertEqual(
            link["target_binding"]["query_input_coverage_sha256"], "f" * 64
        )
        self.assertEqual(link["generation_id"], generation["manifest"]["generation_id"])

    def test_retained_extraction_preserves_https_source_authority(self):
        generation = build_generation(
            [],
            administrator_relationships=[
                envelope(link_updates={"from_authority": "https://apic.example"})
            ],
        )
        extracted = extract_retained_relationships(
            generation["rows"], generation_id=generation["manifest"]["generation_id"]
        )
        self.assertTrue(extracted["complete"])
        self.assertEqual(
            extracted["relationships"][0]["from_authority"], "https://apic.example"
        )

    def test_admin_ingress_fixes_basis_semantics_and_target_authority(self):
        forged_basis = envelope()
        forged_basis["relationships"][0]["basis"] = "native"
        with self.assertRaises(RelationshipError):
            administrator_relationship_collections([forged_basis])
        forged_semantics = envelope()
        forged_semantics["relationships"][0]["semantics"] = "causes"
        with self.assertRaises(RelationshipError):
            administrator_relationship_collections([forged_semantics])
        forged_target = envelope()
        forged_target["relationships"][0]["to_id"] = "checkout-db"
        with self.assertRaises(RelationshipError):
            administrator_relationship_collections([forged_target])

    def test_invalid_binding_components_cannot_be_minted_as_captured_targets(self):
        for update in (
            {"scope": "different-scope"},
            {"window": {"earliest": 1_060, "latest": 1_000}},
            {"graph_result_sha256": "A" * 64},
            {"receipt_basis": "raw_event_lineage"},
            {"query_input_coverage_sha256": "F" * 64},
            {"receipt_fingerprints": ["e" * 64, "d" * 64]},
        ):
            with self.subTest(update=update):
                malformed = envelope()
                malformed["relationships"][0]["binding"].update(update)
                with self.assertRaises(RelationshipError):
                    administrator_relationship_collections([malformed])

    def test_duplicate_evidence_id_with_conflicting_content_fails_closed(self):
        first = envelope()
        second = envelope(link_updates={"valid_to": 1_101})
        second["capture_id"] = "admin-capture-b"
        with self.assertRaisesRegex(RelationshipError, "conflicting content"):
            administrator_relationship_collections([first, second])

    def test_over_limit_relationship_set_is_refused_without_partial_rows(self):
        input_envelope = envelope()
        seed = input_envelope["relationships"][0]
        input_envelope["relationships"] = [
            {
                **copy.deepcopy(seed),
                "evidence_id": f"attestation:edge-{index}",
            }
            for index in range(501)
        ]
        with self.assertRaisesRegex(RelationshipError, "over limit"):
            administrator_relationship_collections([input_envelope])

    def test_correction_is_a_new_generation_and_does_not_mutate_previous_rows(self):
        original = build_generation([], administrator_relationships=[envelope()])
        original_row = copy.deepcopy(original["rows"][0])
        corrected_envelope = envelope(link_updates={"valid_to": 1_050})
        corrected = build_generation(
            [], administrator_relationships=[corrected_envelope]
        )
        self.assertNotEqual(
            original["manifest"]["generation_id"],
            corrected["manifest"]["generation_id"],
        )
        self.assertEqual(original["rows"][0], original_row)
        self.assertEqual(original_row["attributes"]["valid_to"], 1_100)
        self.assertEqual(corrected["rows"][0]["attributes"]["valid_to"], 1_050)


if __name__ == "__main__":
    unittest.main()
