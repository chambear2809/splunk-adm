"""Journal behavior for the disposable synthetic source fixture."""

from contextlib import closing
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "splunk"))
import case_source_capture as fixture  # noqa: E402


class SourceFixtureJournalTest(unittest.TestCase):
    def test_dispatch_is_durable_and_authentication_is_not_journaled(self):
        with tempfile.TemporaryDirectory() as directory:
            scenario = fixture.InstalledInvestigationEvidenceTest()
            scenario.journal = Path(directory) / "journal.jsonl"
            scenario.users = [("synthetic-user", "private-password")]
            body = {"reference": "synthetic", "expected_revision": 2}
            with patch.object(fixture.lab, "urlopen", side_effect=TimeoutError):
                with self.assertRaises(TimeoutError):
                    scenario.request(
                        "POST", "/cases/example/captures", body, "exact-key"
                    )
            contents = scenario.journal.read_text()
            records = [json.loads(line) for line in contents.splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["state"], "dispatching")
            self.assertEqual(records[0]["body"], body)
            self.assertEqual(records[0]["key"], "exact-key")
            self.assertNotIn("private-password", contents)
            self.assertEqual(scenario.journal.stat().st_mode & 0o777, 0o600)

    def test_parent_sync_precedes_dispatch_and_its_failure_blocks_dispatch(self):
        import os
        import stat

        with tempfile.TemporaryDirectory() as directory:
            scenario = fixture.InstalledInvestigationEvidenceTest()
            scenario.journal = Path(directory) / "journal.jsonl"
            scenario.users = [("synthetic-user", "private-password")]
            events = []

            def sync(fd):
                events.append(
                    "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
                )

            def dispatch(*args, **kwargs):
                events.append("dispatch")
                raise TimeoutError

            with (
                patch.object(fixture.os, "fsync", side_effect=sync),
                patch.object(fixture.lab, "urlopen", side_effect=dispatch),
            ):
                with self.assertRaises(TimeoutError):
                    scenario.request(
                        "POST", "/cases", {"title": "synthetic"}, "same-key"
                    )
            self.assertEqual(events, ["file", "directory", "dispatch"])
            with (
                patch.object(fixture.os, "fsync", side_effect=[None, OSError]),
                patch.object(fixture.lab, "urlopen") as request,
            ):
                with self.assertRaises(OSError):
                    scenario.request(
                        "POST", "/cases", {"title": "synthetic"}, "same-key"
                    )
                request.assert_not_called()

    def test_new_outputs_and_runtime_entries_sync_before_external_operations(self):
        from types import SimpleNamespace
        from tools import rehearse_case_source_capture as driver

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(driver.signal, "signal"),
            patch.object(driver, "sync_directory", wraps=driver.sync_directory) as sync,
        ):
            runtime = Path(directory)
            args = SimpleNamespace(
                runtime=runtime,
                package_sha256="synthetic",
                expect_unsupported_helper=False,
            )
            scenario = driver.SourceRehearsal(args)
            self.assertEqual(
                [call.args[0] for call in sync.call_args_list],
                [runtime, runtime.parent],
            )
            self.assertFalse(scenario.created)
            self.assertEqual(scenario.receipt["phases"], {})


class SourceHookCleanupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import case_request_lab as owned

        previous = owned.guard
        try:
            import case_source_faults

            cls.faults = case_source_faults
        finally:
            owned.guard = previous

    @staticmethod
    def restored():
        return {
            "hook_removed": True,
            "hook_restored": True,
            "cache_restored": True,
            "fixture_hook_active": False,
        }

    def test_unknown_install_still_attempts_off_and_restoration(self):
        original = TimeoutError("lost install acknowledgement")
        native = Mock(side_effect=[original, {}, self.restored()])
        journal = Mock()
        with self.assertRaises(TimeoutError) as raised:
            with self.faults.preserved_hook(native, journal):
                self.fail("unknown installation must not start fault work")
        self.assertIs(raised.exception, original)
        self.assertEqual(
            [call.args[0] for call in native.call_args_list],
            ["hook_install", "set_fault", "hook_remove"],
        )
        self.assertEqual(
            journal.call_args.args[0]["outcomes"]["hook_remove"]["state"],
            "acknowledged",
        )

    def test_fault_disable_failure_does_not_skip_restore_or_report_pass(self):
        native = Mock(side_effect=[{}, OSError("off failed"), self.restored()])
        journal = Mock()
        with self.assertRaisesRegex(RuntimeError, "set_fault"):
            with self.faults.preserved_hook(native, journal):
                pass
        self.assertEqual(native.call_args_list[-1].args[0], "hook_remove")
        self.assertEqual(
            journal.call_args.args[0]["outcomes"]["set_fault"]["state"],
            "failed_or_uncertain",
        )

    def test_primary_failure_survives_unknown_restoration(self):
        original = AssertionError("primary failure")
        native = Mock(side_effect=[{}, {}, TimeoutError("lost remove acknowledgement")])
        journal = Mock()
        with self.assertRaises(AssertionError) as raised:
            with self.faults.preserved_hook(native, journal):
                raise original
        self.assertIs(raised.exception, original)
        self.assertTrue(any("hook_remove" in note for note in original.__notes__))
        self.assertEqual(
            journal.call_args.args[0]["outcomes"]["hook_remove"]["state"],
            "failed_or_uncertain",
        )

    def test_missing_restoration_proof_and_journal_failure_refuse_success(self):
        for result in ({}, {**self.restored(), "cache_restored": False}):
            native = Mock(side_effect=[{}, {}, result])
            with self.assertRaisesRegex(RuntimeError, "hook_remove"):
                with self.faults.preserved_hook(native, Mock()):
                    pass
        native = Mock(side_effect=[{}, {}, self.restored()])
        with self.assertRaisesRegex(RuntimeError, "cleanup_journal"):
            with self.faults.preserved_hook(native, Mock(side_effect=OSError)):
                pass
        self.assertEqual(native.call_args_list[-1].args[0], "hook_remove")


class SourceReadinessTest(unittest.TestCase):
    def test_transient_startup_eof_is_retried_with_trusted_hostname(self):
        import ssl
        from unittest.mock import MagicMock
        from tools import rehearse_case_source_capture as driver

        raw = MagicMock()
        context = MagicMock()
        clock = Mock()
        with (
            patch.object(
                driver.socket,
                "create_connection",
                side_effect=[ssl.SSLEOFError("restarting"), raw],
            ),
            patch.object(driver.time, "sleep"),
        ):
            self.assertEqual(driver.wait_tls_ready(35000, context, clock), 1)
        context.wrap_socket.assert_called_once_with(
            raw.__enter__.return_value, server_hostname="127.0.0.1"
        )
        self.assertEqual(clock.call_count, 2)

    def test_bad_certificate_or_readiness_deadline_fails(self):
        import ssl
        from tools import rehearse_case_source_capture as driver

        with (
            patch.object(
                driver.socket,
                "create_connection",
                side_effect=ssl.SSLCertVerificationError("wrong certificate"),
            ) as connection,
            patch.object(driver.time, "sleep") as sleep,
        ):
            with self.assertRaises(ssl.SSLCertVerificationError):
                driver.wait_tls_ready(35000, Mock(), Mock())
            self.assertEqual(connection.call_count, 1)
            sleep.assert_not_called()
        with (
            patch.object(driver.socket, "create_connection", side_effect=OSError),
            patch.object(driver.time, "monotonic", side_effect=[0, 60]),
            patch.object(driver.time, "sleep") as sleep,
        ):
            with self.assertRaises(OSError):
                driver.wait_tls_ready(35000, Mock(), Mock())
            sleep.assert_not_called()


class SourceNativeObservationTest(unittest.TestCase):
    def test_readonly_observation_preserves_receipt_and_owned_job_identity(self):
        import io
        import os
        import sqlite3
        import case_source_native as native

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = root / "cases.sqlite"
            with closing(sqlite3.connect(cases)) as db, db:
                db.execute(
                    "CREATE TABLE requests (principal TEXT, request_id TEXT, action TEXT, case_id TEXT, digest TEXT, result TEXT)"
                )
                db.execute(
                    "INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "atlas_ev_0123456789a",
                        "source-postcommit",
                        "capture",
                        "case-1",
                        "digest",
                        '{"revision":3}',
                    ),
                )
            cases.chmod(0o600)
            ledger = root / "capture_jobs.sqlite"
            with closing(sqlite3.connect(ledger)) as db, db:
                db.execute(
                    "CREATE TABLE jobs (seq INTEGER PRIMARY KEY, principal TEXT, sid TEXT, server_sid TEXT, state TEXT)"
                )
                db.execute(
                    "INSERT INTO jobs VALUES (1, ?, ?, ?, ?)",
                    ("atlas_ev_0123456789a", "intent-1", "server-1", "deleted"),
                )
            ledger.chmod(0o600)
            payload = json.dumps(
                {"principal": "atlas_ev_0123456789a", "request_id": "source-postcommit"}
            )
            file_owner = cases.stat().st_uid
            with (
                patch.object(native, "ROOT", root),
                patch.dict(
                    os.environ, {"ADM_CASE_SOURCE_NATIVE_TASK": "cases-source-20261118"}
                ),
                patch.object(
                    native.os, "getuid", side_effect=[1000, file_owner, file_owner]
                ),
                patch.object(sys, "stdin", io.StringIO(payload)),
            ):
                result = native.main()
            self.assertEqual(result["requests"][0]["case_id"], "case-1")
            self.assertEqual(
                result["jobs"],
                [{"sid": "intent-1", "server_sid": "server-1", "state": "deleted"}],
            )


if __name__ == "__main__":
    unittest.main()
