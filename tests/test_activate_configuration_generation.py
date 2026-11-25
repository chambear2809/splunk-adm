import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools.activate_configuration_generation import (
    ActivationError,
    make_activation,
    main,
    parse_indexed_payload,
    verify_indexed_generation,
    verify_readback,
)
from tools.change_correlation.contracts import canonical_json, sha256_hex
from tools.change_correlation.history import build_generation, row_record_id
from tools.change_correlation.export import render_generation_hec
from tools.capture_networking_fixtures import search as complete_search


class GenerationActivationTest(unittest.TestCase):
    def test_python_generation_matches_shared_browser_contract_fixture(self):
        fixture = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures/change-correlation/shared/activation_python_v1.json"
            ).read_text()
        )
        generation = build_generation(fixture["collections"])
        self.assertEqual(generation["manifest"], fixture["manifest"])
        self.assertEqual(generation["rows"], fixture["rows"])
        expected = fixture["activation"]
        with patch(
            "tools.activate_configuration_generation.time.time",
            return_value=expected["activated_at"],
        ):
            actual = make_activation(
                generation["manifest"],
                generation["rows"],
                index=expected["index"],
                ingest_start=expected["index_earliest"],
                ingest_end=expected["index_latest"],
                attested=True,
            )
        self.assertEqual(actual, expected)
        self.assertEqual(
            actual["source_latest"], generation["manifest"]["source_latest"]
        )

    def setUp(self):
        row = {
            "schema_version": 1,
            "record_type": "change",
            "product": "aci",
            "authority": "apic-a",
            "family": "policy",
            "partition": "tenant-a",
            "scope": "scope-a",
            "object_id": "rule-1",
            "earliest_at": 10,
            "latest_at": 20,
            "field_diffs": [],
        }
        row["record_id"] = row_record_id(row)
        self.manifest = {
            "schema_version": 1,
            "record_type": "generation_manifest",
            "algorithm_version": "configuration-history-v1",
            "canonicalization": "bounded-decimal-json-v1",
            "row_order": "record_id-asc-v1",
            "record_id_hash_excludes": ["record_id", "generation_id"],
            "row_hash_excludes": ["generation_id"],
            "source_receipt_hashes": ["a" * 64],
            "row_count": 1,
            "rows_sha256": sha256_hex(canonical_json(row)),
            "source_earliest": 20,
            "source_latest": 20,
        }
        self.manifest["generation_id"] = sha256_hex(self.manifest)
        row["generation_id"] = self.manifest["generation_id"]
        self.rows = [row]

    def test_full_readback_matches_exact_manifest(self):
        self.assertEqual(verify_readback(self.manifest, self.rows), self.rows)

    def test_indexed_readback_requires_the_exact_manifest(self):
        with self.assertRaisesRegex(ActivationError, "manifest"):
            verify_indexed_generation(self.manifest, self.rows)
        altered = dict(self.manifest, row_count=True)
        with self.assertRaisesRegex(ActivationError, "manifest"):
            verify_indexed_generation(self.manifest, [altered, *self.rows])

    def test_indexed_readback_deduplicates_exact_full_ingest(self):
        payloads = [self.manifest, *self.rows]
        self.assertEqual(
            verify_indexed_generation(self.manifest, payloads * 2), self.rows
        )

    def test_indexed_readback_refuses_conflicting_manifest(self):
        altered = dict(self.manifest, source_latest=21)
        with self.assertRaisesRegex(ActivationError, "manifest"):
            verify_indexed_generation(
                self.manifest, [self.manifest, altered, *self.rows]
            )

    def run_lab_cli(
        self, payloads, *, output_exists=False, raw_encoder=None, strict_responses=None
    ):
        raw_encoder = raw_encoder or (lambda item: canonical_json(item).decode())
        lab = SimpleNamespace(_hec_post=Mock())
        capture = SimpleNamespace(
            search=Mock(
                return_value=(
                    [{"_raw": raw_encoder(p)} for p in payloads],
                    {},
                )
            )
        )
        if strict_responses is not None:
            responses = {
                "dispatch": {"sid": "synthetic-cli", "messages": []},
                "status": {
                    "entry": [
                        {
                            "content": {
                                "dispatchState": "DONE",
                                "isDone": True,
                                "isFinalized": False,
                                "eventIsTruncated": False,
                                "dropCount": 0,
                                "resultCount": len(payloads),
                                "scanCount": len(payloads),
                                "runDuration": 0.001,
                                "messages": [],
                            }
                        }
                    ],
                    "messages": [],
                },
                "results": {
                    "results": [{"_raw": raw_encoder(p)} for p in payloads],
                    "messages": [],
                },
            }
            for stage, mutation in strict_responses.items():
                mutation(responses[stage])

            class Response(io.BytesIO):
                def __init__(self, value, status):
                    super().__init__(json.dumps(value).encode())
                    self.status = status

            def request(method, path, body):
                if method == "POST":
                    stage = "dispatch"
                else:
                    stage = "results" if "/results?" in path else "status"
                return Response(responses[stage], 201 if stage == "dispatch" else 200)

            lab.verify_target = Mock()
            lab._mgmt = Mock(side_effect=request)
            capture.search.side_effect = complete_search
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps(self.manifest))
            output = Path(directory) / "activation.json"
            if output_exists:
                output.write_text("preserve existing output")
            with (
                patch(
                    "tools.activate_configuration_generation.owned_lab",
                    return_value=lab,
                ),
                patch(
                    "tools.activate_configuration_generation.time.time",
                    return_value=1003,
                ),
                patch(
                    "tools.activate_configuration_generation.importlib.util.spec_from_file_location",
                    return_value=spec,
                ),
                patch(
                    "tools.activate_configuration_generation.importlib.util.module_from_spec",
                    return_value=capture,
                ),
            ):
                status = main(
                    [
                        "--manifest",
                        str(manifest),
                        "--lab",
                        "--index",
                        "atlas_changes",
                        "--ingest-start",
                        "1000",
                        "--ingest-end",
                        "1002",
                        "--attest-viewer-entitlement",
                        "--output",
                        str(output),
                    ]
                )
            if output_exists:
                self.assertEqual(output.read_text(), "preserve existing output")
        return status, lab, capture

    def test_lab_cli_never_posts_activation_without_indexed_manifest(self):
        status, lab, _ = self.run_lab_cli(self.rows)
        self.assertEqual(status, 2)
        lab._hec_post.assert_not_called()

    def test_indexed_parser_matches_the_normal_reader_canonical_byte_boundary(self):
        self.assertEqual(
            parse_indexed_payload(canonical_json(self.manifest).decode()), self.manifest
        )
        invalid = [
            json.dumps(self.manifest, indent=2),
            canonical_json(self.manifest).decode() + "\n",
            '{"a":1,"a":1}',
            '{"x":NaN}',
            '{"x":9007199254740992}',
            '{"x":0.0001}',
            "[]",
            "x" * (512 * 1024 + 1),
            "\ud800",
        ]
        for raw in invalid:
            with self.subTest(raw_length=len(raw)), self.assertRaises(ActivationError):
                parse_indexed_payload(raw)

    def test_lab_cli_cannot_publish_noncanonical_indexed_payloads(self):
        status, lab, _ = self.run_lab_cli(
            [self.manifest, *self.rows],
            raw_encoder=lambda item: json.dumps(item, indent=2),
        )
        self.assertEqual(status, 2)
        lab._hec_post.assert_not_called()

    def test_lab_cli_posts_only_after_complete_indexed_generation(self):
        status, lab, capture = self.run_lab_cli([self.manifest, *self.rows] * 2)
        self.assertEqual(status, 0)
        lab._hec_post.assert_called_once()
        query = capture.search.call_args.args[1]
        self.assertIn('sourcetype="adm:configuration_change_manifest:v1"', query)
        self.assertIn("_indextime>=1000 AND _indextime<1002", query)

    def test_strict_cli_search_rejects_all_incomplete_response_diagnostics(self):
        warning = [{"type": "WARN", "text": "synthetic incomplete response"}]
        variants = [
            {"dispatch": lambda value: value.update(messages=warning)},
            {"dispatch": lambda value: value.update(messages={})},
            {"status": lambda value: value.update(messages=warning)},
            {
                "status": lambda value: value["entry"][0]["content"].update(
                    messages=warning
                )
            },
            {"results": lambda value: value.update(messages=warning)},
            {"results": lambda value: value.update(messages="malformed")},
            {"results": lambda value: value.update(resultIsTruncated=True)},
            {"results": lambda value: value.update(results=value["results"] * 6000)},
        ]
        for number, mutation in enumerate(variants):
            with self.subTest(variant=number):
                status, lab, _ = self.run_lab_cli(
                    [self.manifest, *self.rows], strict_responses=mutation
                )
                self.assertEqual(status, 2)
                lab._hec_post.assert_not_called()

    def test_strict_cli_search_accepts_clean_complete_responses_and_canonical_hec(self):
        status, lab, _ = self.run_lab_cli(
            [self.manifest, *self.rows], strict_responses={}
        )
        self.assertEqual(status, 0)
        body = lab._hec_post.call_args.args[0]
        self.assertEqual(body, canonical_json(json.loads(body)))
        self.assertGreaterEqual(lab.verify_target.call_count, 3)

    def test_existing_output_cannot_publish_activation_then_fail(self):
        status, lab, _ = self.run_lab_cli(
            [self.manifest, *self.rows], output_exists=True
        )
        self.assertEqual(status, 2)
        lab._hec_post.assert_not_called()

    def test_manifest_transport_time_is_within_source_query_bounds(self):
        fixture = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures/change-correlation/shared/activation_python_v1.json"
            ).read_text()
        )
        generation = build_generation(fixture["collections"])
        events = [
            json.loads(line)
            for line in render_generation_hec(
                generation, index="atlas_changes"
            ).splitlines()
        ]
        manifest_event = next(
            e for e in events if e["event"]["record_type"] == "generation_manifest"
        )
        self.assertEqual(
            manifest_event["time"], generation["manifest"]["source_latest"]
        )
        payloads = [
            e["event"]
            for e in events
            if e["sourcetype"]
            in {"adm:configuration_change:v1", "adm:configuration_change_manifest:v1"}
        ]
        self.assertEqual(
            verify_indexed_generation(generation["manifest"], payloads),
            generation["rows"],
        )

    def test_empty_audit_receipts_export_numeric_manifest_but_cannot_activate(self):
        fixture = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures/change-correlation/shared/activation_python_v1.json"
            ).read_text()
        )
        empty_audit = dict(fixture["collections"][0], objects=[])
        generation = build_generation([empty_audit])
        self.assertEqual(generation["rows"], [])
        events = [
            json.loads(line)
            for line in render_generation_hec(
                generation, index="atlas_changes"
            ).splitlines()
        ]
        self.assertEqual(events[-1]["time"], empty_audit["received_at"])
        with self.assertRaisesRegex(ActivationError, "empty generation"):
            make_activation(
                generation["manifest"],
                [],
                index="atlas_changes",
                ingest_start=1000,
                ingest_end=1002,
                attested=True,
            )

    def test_exact_replay_deduplicates_before_row_set_validation(self):
        self.assertEqual(verify_readback(self.manifest, self.rows * 2), self.rows)

    def test_missing_row_never_activates(self):
        with self.assertRaises(ActivationError):
            verify_readback(self.manifest, [])

    def test_content_modification_under_same_id_fails(self):
        altered = copy.deepcopy(self.rows)
        altered[0]["scope"] = "scope-b"
        with self.assertRaises(ActivationError):
            verify_readback(self.manifest, altered)

    def test_conflicting_replay_fails(self):
        altered = copy.deepcopy(self.rows[0])
        altered["scope"] = "scope-b"
        with self.assertRaises(ActivationError):
            verify_readback(self.manifest, [*self.rows, altered])

    def test_manifest_tampering_fails(self):
        self.manifest["row_count"] = 0
        with self.assertRaises(ActivationError):
            verify_readback(self.manifest, self.rows)

    def test_capped_input_fails_even_when_duplicates(self):
        with self.assertRaises(ActivationError):
            verify_readback(self.manifest, self.rows * 10001)

    def test_viewer_entitlement_is_explicit(self):
        for attested in (False, None, "true", 1):
            with self.subTest(attested=attested), self.assertRaises(ActivationError):
                make_activation(
                    self.manifest,
                    self.rows,
                    index="atlas_changes",
                    ingest_start=1000,
                    ingest_end=1002,
                    attested=attested,
                )

    def test_activation_retains_separate_ingest_and_source_clocks(self):
        with patch(
            "tools.activate_configuration_generation.time.time", return_value=1002
        ):
            activation = make_activation(
                self.manifest,
                self.rows,
                index="atlas_changes",
                ingest_start=1000,
                ingest_end=1002,
                attested=True,
            )
        self.assertEqual(activation["source_earliest"], 20)
        self.assertEqual(activation["source_latest"], self.manifest["source_latest"])
        self.assertEqual(activation["index_earliest"], 1000)
        self.assertEqual(activation["index_latest"], 1002)
        identity = activation.pop("activation_id")
        self.assertEqual(identity, sha256_hex(activation))

    def test_literal_index_boundary_refuses_spl_injection(self):
        with self.assertRaises(ActivationError):
            make_activation(
                self.manifest,
                self.rows,
                index="x | delete",
                ingest_start=1000,
                ingest_end=1002,
                attested=True,
            )

    def test_ingest_bounds_cannot_be_unknown_or_reversed(self):
        for start, end in ((None, 1002), (1002, 1000), (True, 1002), (0, float("inf"))):
            with self.subTest(start=start, end=end), self.assertRaises(ActivationError):
                make_activation(
                    self.manifest,
                    self.rows,
                    index="atlas_changes",
                    ingest_start=start,
                    ingest_end=end,
                    attested=True,
                )

    def test_reported_event_clock_matches_export_fallback_order(self):
        row = self.rows[0]
        row.update(latest_at=None, event_at=20, observed_at=1000, received_at=1002)
        row["record_id"] = row_record_id(row)
        self.manifest["rows_sha256"] = sha256_hex(
            canonical_json({k: v for k, v in row.items() if k != "generation_id"})
        )
        self.manifest["generation_id"] = sha256_hex(
            {k: v for k, v in self.manifest.items() if k != "generation_id"}
        )
        row["generation_id"] = self.manifest["generation_id"]
        self.assertEqual(verify_readback(self.manifest, self.rows), self.rows)

    def test_signed_but_incorrect_source_extrema_fail(self):
        self.manifest.update(source_earliest=0, source_latest=1)
        self.manifest["generation_id"] = sha256_hex(
            {k: v for k, v in self.manifest.items() if k != "generation_id"}
        )
        self.rows[0]["generation_id"] = self.manifest["generation_id"]
        with self.assertRaisesRegex(ActivationError, "extrema"):
            verify_readback(self.manifest, self.rows)

    def test_future_ingest_interval_cannot_be_activated(self):
        with patch(
            "tools.activate_configuration_generation.time.time", return_value=1001
        ):
            with self.assertRaisesRegex(ActivationError, "close"):
                make_activation(
                    self.manifest,
                    self.rows,
                    index="atlas_changes",
                    ingest_start=1000,
                    ingest_end=1002,
                    attested=True,
                )


if __name__ == "__main__":
    unittest.main()
