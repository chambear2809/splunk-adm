from __future__ import annotations

import unittest

from tools.change_scenarios import load_scenario as load_v1
from tools.change_scenarios_v2 import (
    ScenarioError,
    connected_service_scopes,
    load_scenario,
    load_variant_registry,
    validate_scenario,
)
from tools.raw_fixtures.change_scenarios_v2 import (
    assert_source_phase_buckets,
    prepare_source_inputs,
)


class ScenarioV2Tests(unittest.TestCase):
    def test_v1_module_and_assets_remain_available(self):
        self.assertIsInstance(load_v1("track-a-firewall"), dict)

    def test_v2_registry_is_separate_and_bound(self):
        registry = load_variant_registry()
        self.assertEqual(set(registry["tracks"]), {"track-a-firewall", "track-b-fabric"})
        for scenario_id in registry["tracks"]:
            scenario = load_scenario(scenario_id)
            self.assertIs(validate_scenario(scenario), scenario)
            self.assertEqual(len(connected_service_scopes(scenario)), 2)

    def test_v2_rejects_primary_as_connected_service(self):
        scenario = load_scenario("track-a-firewall")
        bad = dict(scenario)
        bad["connected_services"] = [
            {"application": scenario["application"], "registry_key": "inventory", "role": "x"},
            scenario["connected_services"][1],
        ]
        with self.assertRaises(ScenarioError):
            validate_scenario(bad)

    def test_v2_source_materialization_has_phase_proof_without_receipts(self):
        scenario = load_scenario("track-a-firewall")
        inputs = prepare_source_inputs(
            scenario,
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        self.assertTrue(assert_source_phase_buckets(scenario, inputs, anchor_epoch=1_900_000_200))
        text = repr(inputs)
        self.assertNotIn("indexed_receipt_epoch", text)
        self.assertNotIn("event_fingerprint", text)

    def test_track_b_aci_readback_uses_flattened_ta_event(self):
        scenario = load_scenario("track-b-fabric", "b-aci-attachment")
        inputs = prepare_source_inputs(
            scenario,
            execution_id="00000000-0000-4000-8000-000000000071",
            anchor_epoch=1_900_000_200,
        )
        event = next(item for item in inputs["events"] if item["id"] == "b-aci-endpoint-prelude")
        payload = event["raw_events"][0]["event"]
        self.assertIsInstance(payload, str)
        self.assertIn('\tdn="', payload)
        self.assertIn('\tcomponent="fvCEp"', payload)
        self.assertIn('\tfabricPathDn="', payload)
        self.assertNotIn('"attributes"', payload)
