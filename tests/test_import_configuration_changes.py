"""Offline CLI and HEC envelope tests for configuration history."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.change_correlation.contracts import ContractError
from tools.import_configuration_changes import main


class ImportConfigurationChangesTests(unittest.TestCase):
    def test_cli_bounds_the_file_read_before_parsing(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "oversized.json"
            source.write_bytes(b" " * 65536)
            observed = []

            def reject(content):
                observed.append(len(content))
                raise ContractError("input_limit", "Input exceeds the byte limit.")

            with (
                patch("tools.import_configuration_changes.MAX_INPUT_BYTES", 64),
                patch(
                    "tools.import_configuration_changes.parse_json_document",
                    side_effect=reject,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                status = main(
                    [
                        str(source),
                        "--output-hec",
                        str(root / "output.ndjson"),
                        "--output-manifest",
                        str(root / "manifest.json"),
                        "--index",
                        "atlas_changes",
                    ]
                )
            self.assertEqual(status, 2)
            self.assertEqual(observed, [65])
            self.assertFalse((root / "output.ndjson").exists())

    def _document(self) -> dict:
        return {
            "schema_version": 1,
            "collections": [
                {
                    "schema_version": 1,
                    "capture_id": "cap-1",
                    "product": "aci",
                    "authority": "apic-prod",
                    "source_version": "6.0",
                    "family": "aaa_mod_lr",
                    "partition": "apic-prod-a",
                    "scope": "prod-east",
                    "started_at": 1_000,
                    "completed_at": 1_010,
                    "received_at": 1_011,
                    "status": "complete",
                    "permissions_fingerprint": "perm-sha256-a",
                    "pages_expected": 1,
                    "pages_received": 1,
                    "source_reference": "native-record:aaaModLR-1",
                    "enumeration": "incremental",
                    "deletions_authoritative": False,
                    "objects": [
                        {
                            "object_id": "aaaModLR:1",
                            "observed_at": 1_010,
                            "event_at": None,
                            "effective_at": None,
                            "kind": "audit",
                            "actor": "operator-7",
                            "fields": {
                                "affected_dn": "uni/tn-demo",
                                "event_code": "APIC_MOD",
                                "operation": "modify",
                            },
                        }
                    ],
                }
            ],
        }

    def test_cli_writes_offline_hec_and_manifest_with_admin_index(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "normalized.json"
            hec_path = root / "history.ndjson"
            manifest_path = root / "manifest.json"
            input_path.write_text(json.dumps(self._document()), encoding="utf-8")
            status = main(
                [
                    str(input_path),
                    "--output-hec",
                    str(hec_path),
                    "--output-manifest",
                    str(manifest_path),
                    "--index",
                    "atlas_changes",
                ]
            )
            self.assertEqual(status, 0)
            lines = [json.loads(line) for line in hec_path.read_text().splitlines()]
            self.assertTrue(lines)
            self.assertEqual({line["index"] for line in lines}, {"atlas_changes"})
            self.assertEqual(
                {line["sourcetype"] for line in lines},
                {
                    "adm:configuration_evidence:v1",
                    "adm:configuration_change:v1",
                    "adm:configuration_change_manifest:v1",
                },
            )
            self.assertTrue(
                all(line["source"] == "atlas:configuration_history" for line in lines)
            )
            self.assertEqual(
                json.loads(manifest_path.read_text()),
                next(
                    line["event"] for line in lines if "manifest" in line["sourcetype"]
                ),
            )
            raw = hec_path.read_text()
            self.assertNotIn("changeSet", raw)
            self.assertNotIn("https://", raw)

    def test_unsafe_index_is_rejected_without_writing_outputs(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "normalized.json"
            hec_path = root / "history.ndjson"
            manifest_path = root / "manifest.json"
            input_path.write_text(json.dumps(self._document()), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        str(input_path),
                        "--output-hec",
                        str(hec_path),
                        "--output-manifest",
                        str(manifest_path),
                        "--index",
                        "atlas_changes;|delete",
                    ]
                )
            self.assertEqual(status, 2)
            self.assertFalse(hec_path.exists())
            self.assertFalse(manifest_path.exists())
            self.assertIn("io_error", stderr.getvalue())

    def _run(self, root: Path, *extra: str) -> tuple[int, str]:
        stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(stderr),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            status = main(
                [
                    str(root / "normalized.json"),
                    "--output-hec",
                    str(root / "history.ndjson"),
                    "--output-manifest",
                    str(root / "manifest.json"),
                    "--index",
                    "atlas_changes",
                    *extra,
                ]
            )
        return status, stderr.getvalue()

    def test_existing_outputs_are_not_replaced_without_overwrite(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "normalized.json").write_text(json.dumps(self._document()))
            (root / "manifest.json").write_text("prior")
            status, stderr = self._run(root)
            self.assertEqual(status, 2)
            self.assertIn("output_exists", stderr)
            self.assertEqual((root / "manifest.json").read_text(), "prior")
            self.assertFalse((root / "history.ndjson").exists())
            status, _ = self._run(root, "--overwrite")
            self.assertEqual(status, 0)
            self.assertNotEqual((root / "manifest.json").read_text(), "prior")
            self.assertEqual(
                sorted(p.name for p in root.iterdir()),
                ["history.ndjson", "manifest.json", "normalized.json"],
            )

    def test_manifest_race_removes_new_hec_output(self) -> None:
        from tools import import_configuration_changes as tool

        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "normalized.json").write_text(json.dumps(self._document()))
            real = tool._atomic_write

            def racing(path, content, *, overwrite=False):
                if path.name == "manifest.json":
                    path.write_text("raced")
                return real(path, content, overwrite=overwrite)

            with patch.object(tool, "_atomic_write", side_effect=racing):
                status, stderr = self._run(root)
            self.assertEqual(status, 2)
            self.assertIn("output_exists", stderr)
            self.assertEqual((root / "manifest.json").read_text(), "raced")
            self.assertFalse((root / "history.ndjson").exists())

    def test_failed_overwrite_restores_previous_hec_output(self) -> None:
        from tools import import_configuration_changes as tool

        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "normalized.json").write_text(json.dumps(self._document()))
            (root / "history.ndjson").write_text("previous-hec")
            (root / "manifest.json").write_text("previous-manifest")
            real = tool._atomic_write

            def fail_manifest(path, content, *, overwrite=False):
                if path.name == "manifest.json":
                    raise OSError("disk full")
                return real(path, content, overwrite=overwrite)

            with patch.object(tool, "_atomic_write", side_effect=fail_manifest):
                status, stderr = self._run(root, "--overwrite")
            self.assertEqual(status, 2)
            self.assertIn("io_error", stderr)
            self.assertEqual((root / "history.ndjson").read_text(), "previous-hec")
            self.assertEqual((root / "manifest.json").read_text(), "previous-manifest")
            self.assertEqual(
                sorted(p.name for p in root.iterdir()),
                ["history.ndjson", "manifest.json", "normalized.json"],
            )

    def test_invalid_json_error_does_not_echo_secret_text(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "invalid.json"
            hec_path = root / "history.ndjson"
            manifest_path = root / "manifest.json"
            input_path.write_text('{"password":"very-secret-marker"', encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        str(input_path),
                        "--output-hec",
                        str(hec_path),
                        "--output-manifest",
                        str(manifest_path),
                        "--index",
                        "atlas_changes",
                    ]
                )
            self.assertEqual(status, 2)
            self.assertIn("invalid_json", stderr.getvalue())
            self.assertNotIn("very-secret-marker", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
