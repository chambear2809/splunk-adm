import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import qualification_evidence as qe


class QualificationEvidenceTests(unittest.TestCase):
    def setUp(self):
        # A real CI SHA must not conflict with this fixture's controlled source.
        environment = mock.patch.dict(qe.os.environ, {"GITHUB_SHA": "commit"})
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "tools").mkdir()
        (self.root / "tools" / "marker.py").write_text("one\n", encoding="utf-8")
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.package = self.dist / "splunk_adm-1.0.0.tar.gz"
        self.package.write_bytes(b"package")
        digest = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.package.with_name(self.package.name + ".sha256").write_text(
            f"{digest}  {self.package.name}\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self, stage="offline"):
        directory = self.root / stage
        source = {"sha256": "source", "commit": "commit", "tree": "tree", "files": []}
        with mock.patch.object(qe, "_source_fingerprint", return_value=source):
            qe.start(
                type(
                    "Args",
                    (),
                    {
                        "directory": directory,
                        "stage": stage,
                        "package": ["dist/splunk_adm-1.0.0.tar.gz"],
                        "root": self.root,
                    },
                )()
            )
        return directory

    def test_start_snapshots_package_and_refuses_bad_sidecar(self):
        directory = self.manifest()
        self.assertTrue((directory / "artifacts" / self.package.name).exists())
        self.package.with_name(self.package.name + ".sha256").write_text(
            "0" * 64 + "  wrong\n", encoding="utf-8"
        )
        with self.assertRaises(qe.EvidenceError):
            qe.start(
                type(
                    "Args",
                    (),
                    {
                        "directory": self.root / "bad",
                        "stage": "offline",
                        "package": ["dist/splunk_adm-1.0.0.tar.gz"],
                        "root": self.root,
                    },
                )
            )

    def test_finish_rejects_source_or_package_drift(self):
        directory = self.manifest()
        (self.root / "tools" / "marker.py").write_text("changed\n", encoding="utf-8")
        self.package.write_bytes(b"changed package")
        self.assertEqual(
            qe.finish(
                type(
                    "Args",
                    (),
                    {
                        "directory": directory,
                        "root": self.root,
                        "require": [],
                        "appinspect_report": None,
                    },
                )
            ),
            1,
        )
        self.assertEqual(
            json.loads((directory / "manifest.json").read_text())["status"], "failed"
        )

    def test_run_refuses_duplicate_and_preserves_new_manifest(self):
        directory = self.manifest()
        args = type(
            "Args",
            (),
            {
                "directory": directory,
                "root": self.root,
                "check": "release",
                "command": ["--", "true"],
            },
        )
        with mock.patch.object(
            qe.subprocess, "run", return_value=mock.Mock(returncode=0)
        ):
            self.assertEqual(qe.run_check(args), 0)
        with self.assertRaisesRegex(qe.EvidenceError, "duplicate"):
            qe.run_check(args)

    def test_appinspect_summary_is_allowlisted_and_redacts_messages(self):
        report = self.root / "report.json"
        report.write_text(
            json.dumps(
                {
                    "reports": [
                        {
                            "groups": [
                                {
                                    "checks": [
                                        {
                                            "result": "success",
                                            "messages": [
                                                {
                                                    "result": "warning",
                                                    "message": "/private/path",
                                                }
                                            ],
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        summary = qe._appinspect_summary(report)
        self.assertEqual(summary["counts"]["success"], 1)
        self.assertEqual(summary["counts"]["warning"], 0)
        self.assertNotIn("message", summary)

    def test_runtime_allowlist_does_not_copy_server_payload(self):
        directory = self.manifest("offline")
        fake = {
            "entry": [
                {
                    "content": {
                        "version": "10.6.0.5",
                        "build": "123456",
                        "product_type": "enterprise",
                        "password": "secret",
                    }
                }
            ]
        }
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(json.dumps(fake).encode())
        with mock.patch("tests.splunk.lab._mgmt", return_value=response):
            self.assertEqual(
                qe.lab_runtime(type("Args", (), {"directory": directory})()), 0
            )
        value = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(
            value["runtime"]["splunk"],
            {
                "version": "10.6.0.5",
                "build": "123456",
                "product_type": "enterprise",
            },
        )

    def test_runtime_build_requires_an_actual_identifier(self):
        runtime = {
            "version": "10.6.0.5",
            "build": "123abc",
            "product_type": "enterprise",
        }
        self.assertTrue(qe._valid_runtime(runtime))
        for placeholder in (
            "unknown",
            "Unavailable",
            "none",
            "null",
            "-",
            ".",
            "build",
        ):
            with self.subTest(build=placeholder):
                self.assertFalse(qe._valid_runtime({**runtime, "build": placeholder}))

    def test_verify_rejects_forged_complete_packet_and_tampered_snapshot(self):
        directory = self.manifest()
        value = json.loads((directory / "manifest.json").read_text())
        value.update(
            {
                "status": "complete",
                "outcomes": {
                    "appinspect": {"valid": True, "counts": {}, "sha256": "report"}
                },
            }
        )
        value["checks"] = [
            {"name": name, "status": "passed"}
            for name in ("release", "atlas_bundle", "appinspect")
        ]
        qe._write(directory, value)
        (directory / value["packages"][0]["snapshot"]).write_bytes(b"tampered")
        with self.assertRaises(qe.EvidenceError):
            qe._verify_packet(directory, "offline")

    def test_verify_rejects_stage_mismatch_and_missing_required_checks(self):
        directory = self.manifest()
        value = json.loads((directory / "manifest.json").read_text())
        value["status"] = "complete"
        qe._write(directory, value)
        with self.assertRaises(qe.EvidenceError):
            qe._verify_packet(directory, "installed")
        with self.assertRaises(qe.EvidenceError):
            qe._verify_packet(directory, "offline")


if __name__ == "__main__":
    unittest.main()
