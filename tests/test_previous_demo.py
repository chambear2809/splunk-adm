"""Offline grounding checks for the preceding ACI demo capture."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

from tools.gen_raw_fixtures import (
    AciScenario,
    aci_outputs,
    epoch,
    parse,
    previous_aci_scenario,
)

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = json.loads((ROOT / "fixtures/raw-aci/scenario.json").read_text())
CAPTURE = ROOT / "fixtures/demo-rows-aci-prev.json"


def _timestamps(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _timestamps(item)
    elif isinstance(value, list):
        for item in value:
            yield from _timestamps(item)
    elif isinstance(value, str) and "T" in value and value.endswith("Z"):
        yield value


class PreviousDemoTest(unittest.TestCase):
    def test_previous_scenario_is_equal_prior_window_and_omits_blocked_conversation(
        self,
    ):
        previous = previous_aci_scenario(SCENARIO)
        self.assertEqual(
            previous["window"],
            {"start": "2026-10-07T11:30:00Z", "end": "2026-10-07T11:45:00Z"},
        )
        self.assertNotIn(
            "c8-blocked-db", {item["id"] for item in previous["conversations"]}
        )
        self.assertEqual(
            len(previous["conversations"]), len(SCENARIO["conversations"]) - 1
        )
        self.assertEqual(
            previous["kubernetes"]["pods"][0]["start"], "2026-10-07T08:45:00Z"
        )
        self.assertEqual(
            previous["traces"][0]["spans"][0]["start"], "2026-10-07T11:35:10.050Z"
        )
        base_without_block = dict(
            SCENARIO,
            conversations=[
                item
                for item in SCENARIO["conversations"]
                if item["id"] != "c8-blocked-db"
            ],
        )
        shifted, original = (
            list(_timestamps(previous)),
            list(_timestamps(base_without_block)),
        )
        self.assertEqual(len(shifted), len(original))
        self.assertGreater(len(shifted), 90)
        self.assertTrue(
            all(
                (parse(after) - parse(before)).total_seconds() == -900
                for before, after in zip(original, shifted)
            )
        )

    def test_previous_generator_emits_same_grounded_streams_without_edge_batch(self):
        previous = previous_aci_scenario(SCENARIO)
        outputs = aci_outputs(AciScenario(previous))
        self.assertEqual(
            set(outputs),
            {
                "stream_netflow.ndjson",
                "nd_flows.ndjson",
                "nd_endpoints.ndjson",
                "aci_stats.ndjson",
                "aci_class.ndjson",
                "kube_objects.ndjson",
                "hubble_flows.ndjson",
                "isovalent.ndjson",
                "otel_traces.ndjson",
            },
        )
        end = epoch(parse(previous["window"]["end"]))
        for events in outputs.values():
            self.assertTrue(events)
            self.assertTrue(all(event["time"] <= end for event in events))
            self.assertTrue(
                all("c8-blocked-db" not in json.dumps(event) for event in events)
            )

    def test_captured_previous_rows_are_macro_grounded_when_present(self):
        captured = json.loads(CAPTURE.read_text())
        self.assertEqual(
            (captured["earliest"], captured["latest"]), ("1791372600", "1791373500")
        )
        self.assertEqual(
            captured["search"], '`adm_graph("frontend","demo","demo-cluster","shop")`'
        )
        rows = captured["rows"]
        row_types = {row.get("row_type") for row in rows}
        self.assertTrue(rows)
        self.assertTrue(row_types <= {"node", "edge", "meta"})
        self.assertTrue({"node", "edge", "meta"} <= row_types)
        allowed = self._adm_graph_output_fields()
        for row in rows:
            self.assertTrue(
                all(field in allowed or field.startswith("attr_") for field in row), row
            )
        provenance = captured["provenance"]
        self.assertEqual(
            provenance["source"], "splunk_app/splunk_adm/default/macros.conf:adm_graph"
        )
        for key, path in [
            ("macro_file_sha256", "splunk_app/splunk_adm/default/macros.conf"),
            ("generator_sha256", "tools/gen_raw_fixtures.py"),
            ("scenario_sha256", "fixtures/raw-aci/scenario.json"),
        ]:
            self.assertEqual(
                provenance[key], hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            )
        macro = re.search(
            r"\[adm_graph\(4\)\]\n(?P<body>.*?)(?=\n\[|\Z)",
            (ROOT / "splunk_app/splunk_adm/default/macros.conf").read_text(),
            re.S,
        )
        self.assertIsNotNone(macro)
        self.assertEqual(
            provenance["macro_sha256"],
            hashlib.sha256(macro.group("body").strip().encode()).hexdigest(),
        )

    def test_helper_changes_invalidate_source_hash(self):
        import tempfile
        from tools.capture_previous_demo import source_hash

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "macros.conf"
            path.write_text(
                "[adm_graph(4)]\ndefinition = `helper`\n[helper]\ndefinition = old\n"
            )
            previous = source_hash(path)
            path.write_text(
                path.read_text().replace("definition = old", "definition = changed")
            )
            self.assertNotEqual(previous, source_hash(path))

    @staticmethod
    def _adm_graph_output_fields():
        text = (ROOT / "splunk_app/splunk_adm/default/macros.conf").read_text()
        body = re.search(
            r"\[adm_graph_output\(4\)\]\n(?P<body>.*?)(?=\n\[|\Z)", text, re.S
        ).group("body")
        fields = next(
            match
            for match in re.findall(r"\| fields ([^|\n]+)", body.replace("\\\n", " "))
            if match.startswith("row_type id ")
        )
        return set(fields.replace("\\", "").split())
