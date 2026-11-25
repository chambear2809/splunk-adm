from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from tools.change_scenario_v2_capture import (
    ConnectedBundleError,
    build_connected_bundle,
    verify_connected_bundle,
)
from tools.raw_fixtures.change_scenarios_v2 import native_payload_sha256
from tools.change_scenarios import load_scenario as load_v1


class ConnectedScenarioBundleTests(unittest.TestCase):
    def test_committed_python_fixture_verifies(self):
        fixture = (
            Path(__file__).parents[1]
            / "fixtures/change-correlation-v2/connected-bundle-track-b.json"
        )
        self.assertEqual(
            verify_connected_bundle(json.loads(fixture.read_text())),
            json.loads(fixture.read_text()),
        )

    def test_python_builds_and_verifies_connected_bundle(self):
        bundle = build_connected_bundle(
            "track-b-fabric",
            variant_id="b-aci-attachment",
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        self.assertEqual(verify_connected_bundle(bundle), bundle)
        self.assertTrue(bundle["phase_proof"])

    def test_bundle_tampering_and_receipt_claims_fail_closed(self):
        bundle = build_connected_bundle(
            "track-a-firewall",
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        tampered = copy.deepcopy(bundle)
        tampered["events"][0]["indexed_receipt_epoch"] = 1
        with self.assertRaises(ConnectedBundleError):
            verify_connected_bundle(tampered)

    def test_rehashed_mutation_is_rejected_by_deterministic_regeneration(self):
        bundle = build_connected_bundle(
            "track-b-fabric",
            variant_id="b-aci-attachment",
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        tampered = copy.deepcopy(bundle)
        tampered["application"]["service"] = "other"
        from tools.change_correlation.contracts import canonical_json, sha256_hex

        tampered["bundle_sha256"] = sha256_hex(
            canonical_json({k: v for k, v in tampered.items() if k != "bundle_sha256"})
        )
        with self.assertRaises(ConnectedBundleError):
            verify_connected_bundle(tampered)

    def test_v1_scenario_remains_the_original_contract(self):
        self.assertEqual(load_v1("track-a-firewall")["schema_version"], 1)

    def test_all_track_payload_hashes_match_portable_content(self):
        for scenario_id, variant_id in (
            ("track-a-firewall", None),
            ("track-b-fabric", None),
        ):
            bundle = build_connected_bundle(
                scenario_id,
                variant_id=variant_id,
                execution_id="00000000-0000-4000-8000-000000000071",
                anchor_epoch=1_900_000_200,
            )
            for event in bundle["events"]:
                for ordinal, readback in enumerate(event.get("readback_expected", [])):
                    raw = event.get("raw_events", [])[ordinal]
                    self.assertEqual(
                        readback["native_payload_sha256"],
                        native_payload_sha256(raw.get("event")),
                    )
