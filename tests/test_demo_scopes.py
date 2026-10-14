from __future__ import annotations

import json
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"
FIELDS = ["environment", "cluster", "namespace", "service", "last_seen", "pods"]


class DemoScopeGroundingTest(unittest.TestCase):
    def test_scope_macro_is_grounded_and_has_exact_output_schema(self) -> None:
        text = MACROS.read_text(encoding="utf-8")
        match = re.search(
            r"\[adm_scope_options\]\n(?P<body>.*?)(?=\n\[|\Z)", text, re.S
        )
        self.assertIsNotNone(match)
        body = match.group("body")
        self.assertIn("inputlookup adm_service_workload", body)
        self.assertIn('fillnull value="" environment cluster namespace service', body)
        self.assertIn("max(last_seen) AS last_seen", body)
        self.assertIn("dc(pod_uid) AS pods", body)
        self.assertIn("by environment cluster namespace service", body)
        self.assertIn(
            "| fields environment cluster namespace service last_seen pods", body
        )
        self.assertNotRegex(body, r"\| fields .*\b(adm_|pod_uid)\b")

    def test_captured_fixture_exists_and_has_exact_schema(self) -> None:
        path = ROOT / "fixtures/demo-scopes.json"
        self.assertTrue(path.exists(), f"missing real capture: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["search"], "| `adm_scope_options`")
        self.assertTrue({"earliest", "latest", "provenance", "rows"} <= payload.keys())
        self.assertTrue(payload["rows"])
        body = (
            re.search(
                r"\[adm_scope_options\]\n(?P<body>.*?)(?=\n\[|\Z)",
                MACROS.read_text(encoding="utf-8"),
                re.S,
            )
            .group("body")
            .strip()
        )
        self.assertEqual(
            payload["provenance"].get("macro_sha256"),
            hashlib.sha256(body.encode()).hexdigest(),
        )
        self.assertEqual(payload["provenance"].get("schema"), FIELDS)
        self.assertTrue(
            set(payload["provenance"].get("input_fields", []))
            >= {"service", "environment", "cluster", "namespace"}
        )
        for row in payload["rows"]:
            self.assertEqual(list(row), FIELDS)
