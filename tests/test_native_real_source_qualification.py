import copy
import unittest
import json
import pathlib
import os
import subprocess
import sys
import tempfile
from unittest import mock

from tools.qualify_native_real_source import (
    check_summary,
    installed_request,
    operation_spec,
    journal_append,
    journal_events,
)


class RealSourceQualificationTests(unittest.TestCase):
    def setUp(self):
        h = "a" * 64
        self.capture = {
            key: h
            for key in (
                "request_body_sha256",
                "request_key_sha256",
                "path_sha256",
                "caller_sha256",
                "capture_id_sha256",
                "evidence_sha256",
                "config_revision_sha256",
            )
        }
        self.capture.update(dispatch="completed", supervised_transport_verified=True)
        self.summary = {
            "source": {
                **dict.fromkeys(
                    (
                        "product",
                        "version",
                        "index",
                        "sourcetype",
                        "source",
                        "authority",
                        "scope",
                    ),
                    "example",
                ),
                **dict.fromkeys(
                    (
                        "schema_evidence_sha256",
                        "provenance_sha256",
                        "config_revision_sha256",
                    ),
                    h,
                ),
                "real": True,
            },
            "entitlement": {
                **dict.fromkeys(
                    ("principal", "effective_roles", "index_access", "search_filter"),
                    "example",
                ),
                "evidence_sha256": h,
                "current_verified": True,
            },
            "coverage": {
                **dict.fromkeys(
                    (
                        "historical_scope",
                        "loss_limit",
                        "lateness_limit",
                        "clock_uncertainty",
                    ),
                    "unknown, documented",
                ),
                "evidence_sha256": h,
            },
            "windows": [
                {"start": "2026-11-18T10:00:00Z", "end": "2026-11-18T10:05:00Z"},
                {"start": "2026-11-18T10:05:00Z", "end": "2026-11-18T10:10:00Z"},
            ],
            "capture": self.capture,
            "phases": {},
        }
        for name in (
            "allowed",
            "permission_revoked",
            "permission_restored",
            "config_changed",
            "config_restored",
        ):
            result = (
                "withheld"
                if name in ("permission_revoked", "config_changed")
                else "visible"
            )
            observation = {
                "dispatch": "completed",
                "result": result,
                "response_evidence_sha256": h,
            }
            self.summary["phases"][name] = {
                "effective_state_verified": True,
                "state_evidence_sha256": h,
                "stored_read": {**observation, "capture_id_sha256": h},
                "selected_export": {**observation, "capture_id_sha256": h},
                "original_retry": {
                    **observation,
                    **{
                        key: self.capture[key]
                        for key in (
                            "request_body_sha256",
                            "request_key_sha256",
                            "path_sha256",
                            "caller_sha256",
                        )
                    },
                },
            }

    def test_complete_shape_is_not_independent_proof(self):
        self.assertEqual(check_summary(self.summary), [])

    def test_uncertain_dispatch_and_changed_original_are_not_success(self):
        retry = self.summary["phases"]["permission_revoked"]["original_retry"]
        retry.update(dispatch="uncertain", request_key_sha256="b" * 64)
        gaps = check_summary(self.summary)
        self.assertIn("permission_revoked.original_retry.dispatch", gaps)
        self.assertIn("permission_revoked.original_retry.request_key_sha256", gaps)

    def test_wrong_selection_or_nonwithheld_export_fails(self):
        export = self.summary["phases"]["config_changed"]["selected_export"]
        export.update(capture_id_sha256="b" * 64, result="visible")
        gaps = check_summary(self.summary)
        self.assertIn("config_changed.selected_export.selection", gaps)
        self.assertIn("config_changed.selected_export.result", gaps)

    def test_windows_must_be_ordered_equal_and_bounded(self):
        for bad in ("2026-11-18T10:11:00Z", "2026-11-18T10:09:00Z", "invalid"):
            sample = copy.deepcopy(self.summary)
            sample["windows"][1]["end"] = bad
            self.assertIn("windows.comparable", check_summary(sample))

    def test_missing_entitlement_real_source_and_revision_are_gaps(self):
        self.summary["entitlement"]["current_verified"] = False
        self.summary["source"]["real"] = False
        self.summary["capture"]["config_revision_sha256"] = "b" * 64
        gaps = check_summary(self.summary)
        self.assertIn("entitlement.current_verified", gaps)
        self.assertIn("source.real", gaps)
        self.assertIn("capture.source_revision_match", gaps)

    def test_missing_or_malformed_values_are_not_accepted(self):
        self.assertIn("summary_object", check_summary(None))
        self.summary["phases"]["allowed"] = None
        self.assertIn("allowed.stored_read.dispatch", check_summary(self.summary))


class InstalledDriverTests(unittest.TestCase):
    def test_exact_retry_uses_original_body_key_and_caller(self):
        caller = {"action": "retry", "username": "investigator"}
        original = {
            "state": "dispatching",
            "action": "capture",
            "caller": "investigator",
            "method": "POST",
            "path": "/cases/id/captures",
            "body": '{ "exact": 1 }',
            "key": "original",
        }
        self.assertEqual(operation_spec(caller, original)["body"], original["body"])
        self.assertEqual(operation_spec(caller, original)["key"], "original")
        with self.assertRaises(ValueError):
            operation_spec({**caller, "username": "other"}, original)

    def test_ambiguous_capture_remains_durable_before_disconnect(self):
        info = {
            "entry": [
                {
                    "content": {
                        "guid": "test-guid",
                        "version": "10.6.0.5",
                        "activeLicenseGroup": "Enterprise",
                    }
                }
            ]
        }

        class Reply:
            status = 200

            def read(self, _limit):
                return json.dumps(info).encode()

        class Connection:
            count = 0

            def __init__(self, *args, **kwargs):
                pass

            def request(self, *args, **kwargs):
                Connection.count += 1
                if Connection.count == 2:
                    raise OSError("private transport detail")

            def getresponse(self):
                return Reply()

            def close(self):
                pass

        import hashlib

        guid_hash = hashlib.sha256(b"test-guid").hexdigest()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch("tools.qualify_native_real_source.ssl.create_default_context"),
            mock.patch(
                "tools.qualify_native_real_source.http.client.HTTPSConnection",
                Connection,
            ),
            mock.patch(
                "tools.qualify_native_real_source.SERVER_GUID_SHA256", guid_hash
            ),
        ):
            stage = pathlib.Path(tmp) / "evidence"
            command = {
                "username": "investigator",
                "password": "private-secret",
                "action": "capture",
                "case_id": "12345678-1234-4123-8123-123456789abc",
                "body": {"expected_revision": 1, "reference": {}, "label": "test"},
            }
            result = installed_request(command, stage)
            records = [
                json.loads(line)
                for line in (stage / "operations.jsonl").read_text().splitlines()
            ]
            self.assertEqual(result["state"], "uncertain")
            self.assertEqual(
                [row["state"] for row in records], ["dispatching", "uncertain"]
            )
            self.assertTrue(records[0]["key"])
            self.assertNotIn("private-secret", json.dumps(records))
            self.assertNotIn("private transport detail", json.dumps(records))
            with self.assertRaises(ValueError):
                installed_request(command, stage)

    def test_fifo_journal_never_blocks_reader_or_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = pathlib.Path(tmp)
            os.mkfifo(stage / "operations.jsonl", 0o600)
            snippet = """from pathlib import Path
from tools.qualify_native_real_source import journal_events, journal_append
import sys
p = Path(sys.argv[1])
for func, args in ((journal_events, (p,)), (journal_append, (p, {'state':'test'}))):
    try:
        func(*args)
    except (ValueError, OSError):
        continue
    raise SystemExit(1)
"""
            result = subprocess.run(
                [sys.executable, "-c", snippet, tmp], timeout=3, check=False
            )
            self.assertEqual(result.returncode, 0)

    def test_interrupted_response_tail_retained_and_exact_retry(self):
        import base64
        import hashlib

        operation = "12345678-1234-4123-8123-123456789abc"
        original = {
            "state": "dispatching",
            "action": "capture",
            "operation": operation,
            "caller": "alice",
            "method": "POST",
            "path": "/cases/12345678-1234-4123-8123-123456789abc/captures",
            "body": '{ "reference": "exact" }',
            "key": "original-key",
        }
        info = {
            "entry": [
                {
                    "content": {
                        "guid": "test-guid",
                        "version": "10.6.0.5",
                        "activeLicenseGroup": "Enterprise",
                    }
                }
            ]
        }

        class Reply:
            status = 200

            def __init__(self, value):
                self.value = value

            def read(self, _limit):
                return json.dumps(self.value).encode()

        class Connection:
            sent = []

            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, path, body=None, headers=None):
                self.sent.append((method, path, body, headers))

            def getresponse(self):
                return Reply(info if len(self.sent) == 1 else {"captures": []})

            def close(self):
                pass

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch("tools.qualify_native_real_source.ssl.create_default_context"),
            mock.patch(
                "tools.qualify_native_real_source.http.client.HTTPSConnection",
                Connection,
            ),
            mock.patch(
                "tools.qualify_native_real_source.SERVER_GUID_SHA256",
                hashlib.sha256(b"test-guid").hexdigest(),
            ),
        ):
            stage = pathlib.Path(tmp) / "stage"
            stage.mkdir(mode=0o700)
            journal_append(stage, original)
            with (stage / "operations.jsonl").open("ab") as stream:
                stream.write(b'{"state":"response","result":')
            result = installed_request(
                {
                    "action": "retry",
                    "original_operation": operation,
                    "username": "alice",
                    "password": "secret",
                },
                stage,
            )
            self.assertEqual(result["status"], 200)
            self.assertEqual(Connection.sent[1][2], original["body"])
            self.assertEqual(Connection.sent[1][3]["Idempotency-Key"], original["key"])
            self.assertEqual(
                Connection.sent[1][3]["Authorization"],
                "Basic " + base64.b64encode(b"alice:secret").decode(),
            )
            events = journal_events(stage)
            marker = next(
                event for event in events if event["state"] == "tail_quarantined"
            )
            self.assertEqual(
                (stage / marker["file"]).read_bytes(), b'{"state":"response","result":'
            )
            self.assertEqual(events[0], original)

    def test_non_tail_corruption_and_missing_original_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = pathlib.Path(tmp)
            (stage / "operations.jsonl").write_bytes(b'{invalid}\n{"state":"ok"}\n')
            os.chmod(stage / "operations.jsonl", 0o600)
            with self.assertRaises(ValueError):
                journal_events(stage)
            self.assertFalse(list(stage.glob("journal-tail-*")))
            (stage / "operations.jsonl").write_bytes(b'{"state":"response"')
            with self.assertRaises(ValueError):
                installed_request(
                    {
                        "action": "retry",
                        "original_operation": "12345678-1234-4123-8123-123456789abc",
                        "username": "alice",
                        "password": "secret",
                    },
                    stage,
                )
            self.assertEqual(len(list(stage.glob("journal-tail-*"))), 1)

    def test_invalid_selection_is_refused(self):
        with self.assertRaises(ValueError):
            operation_spec({"action": "export", "case_id": "bad", "capture_id": "bad"})


if __name__ == "__main__":
    unittest.main()
