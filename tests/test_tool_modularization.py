"""Compatibility of public imports used before tool extraction."""

import json
from pathlib import Path
import unittest

from tools import gen_raw_fixtures as generator

ROOT = Path(__file__).resolve().parents[1]


class LegacyGeneratorImportsTest(unittest.TestCase):
    def test_aci_import_is_callable_and_retains_fixture_output_contract(self):
        self.assertTrue(callable(generator.aci))
        scenario = generator.Scenario(
            json.loads((ROOT / "fixtures/raw/scenario.json").read_text())
        )
        stats, classes = generator.aci(scenario)
        for name, events in (
            ("aci_stats.ndjson", stats),
            ("aci_class.ndjson", classes),
        ):
            expected = [
                json.loads(line)
                for line in (ROOT / "fixtures/raw" / name).read_text().splitlines()
                if line
            ]
            self.assertEqual(sorted(events, key=lambda event: event["time"]), expected)
