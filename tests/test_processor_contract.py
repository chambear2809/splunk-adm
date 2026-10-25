"""Offline tests for the optional Edge and Ingest Processor artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.validate_processor_contract import (
    ProcessorContractError,
    canonical_sha256,
    strict_json_loads,
    validate_processor_contract,
)

ROOT = Path(__file__).resolve().parents[1]


class ProcessorContractTest(unittest.TestCase):
    def test_offline_artifacts_validate_without_claiming_processor_execution(self):
        result = validate_processor_contract(ROOT)

        self.assertEqual(result["qualification"], "offline_semantic_expectations_only")
        self.assertIs(result["processors_executed"], False)
        self.assertEqual(result["netflow_records"], 42)
        self.assertEqual(result["health_metric_records"], 5)
        self.assertEqual(result["health_completion_records"], 1)
        self.assertEqual(
            result["runtime_qualification"]["edge_processor"], "unqualified"
        )
        self.assertEqual(
            result["runtime_qualification"]["ingest_processor"], "unqualified"
        )

    def test_strict_json_rejects_duplicate_keys_and_non_json_numbers(self):
        for text in ('{"event":1,"event":2}', '{"value":NaN}', '{"event":'):
            with self.subTest(text=text), self.assertRaises(ProcessorContractError):
                strict_json_loads(text)

    def test_canonical_hash_ignores_object_key_order_but_preserves_array_order(self):
        self.assertEqual(
            canonical_sha256({"a": 1, "b": 2}), canonical_sha256({"b": 2, "a": 1})
        )
        self.assertNotEqual(canonical_sha256([1, 2]), canonical_sha256([2, 1]))

    def test_unpacked_processor_toolkit_is_self_contained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "integrations", root / "integrations")
            shutil.copytree(
                ROOT / "fixtures" / "processors", root / "fixtures" / "processors"
            )
            result = validate_processor_contract(root)
        self.assertEqual(result["netflow_records"], 42)
        self.assertEqual(result["otel_external_fields_records"], 1)

    def test_validator_rejects_changed_pipeline_routing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "integrations", root / "integrations")
            shutil.copytree(
                ROOT / "fixtures" / "processors", root / "fixtures" / "processors"
            )
            pipeline = root / "integrations/processors/v1/edge/stream_netflow.spl2"
            pipeline.write_text(
                pipeline.read_text(encoding="utf-8").replace(
                    'index="netflow"', 'index="other"'
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ProcessorContractError, "reviewed index-routing identity pipeline"
            ):
                validate_processor_contract(root)

    def test_manifest_negative_inputs_are_not_valid_json(self):
        manifest = json.loads(
            (ROOT / "fixtures/processors/v1/manifest.json").read_text(encoding="utf-8")
        )
        for name in ("duplicate_json_key", "malformed_json"):
            path = manifest["negative_inputs"][name]
            raw = (ROOT / path).read_text(encoding="utf-8").strip()
            with self.subTest(path=path), self.assertRaises(ProcessorContractError):
                strict_json_loads(raw)

        unmatched = (
            (ROOT / manifest["negative_inputs"]["unmatched_sourcetype"])
            .read_text(encoding="utf-8")
            .strip()
        )
        self.assertNotIn(
            strict_json_loads(unmatched)["sourcetype"], manifest["selected_sourcetypes"]
        )


if __name__ == "__main__":
    unittest.main()
