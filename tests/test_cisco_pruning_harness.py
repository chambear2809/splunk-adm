"""Pure safety checks for the destructive fixture qualification harness."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.splunk import test_cisco_pruning as pruning
from tests.splunk.test_cisco_pruning import (
    _active_app_job,
    _collection_read,
    _schedule_state,
)


class PruningHarnessSafetyTest(unittest.TestCase):
    def test_pause_requires_unambiguous_schedule_aliases(self):
        self.assertTrue(_schedule_state({"is_scheduled": "1", "enableSched": True}))
        for content in (
            {},
            {"is_scheduled": "unknown"},
            {"is_scheduled": False, "enableSched": True},
        ):
            with self.assertRaises(AssertionError):
                _schedule_state(content)

    def test_finalizing_is_active_even_if_is_done_is_set(self):
        for done in (False, True, "0", "1"):
            self.assertTrue(
                _active_app_job(
                    {
                        "acl": {"app": "splunk_adm"},
                        "content": {"dispatchState": "FINALIZING", "isDone": done},
                    }
                )
            )
        self.assertTrue(
            _active_app_job(
                {
                    "content": {
                        "label": "ADM - Network client history builder",
                        "dispatchState": "FINALIZING",
                    }
                }
            )
        )
        self.assertFalse(
            _active_app_job(
                {
                    "acl": {"app": "splunk_adm"},
                    "content": {"dispatchState": "DONE", "isDone": True},
                }
            )
        )
        self.assertFalse(
            _active_app_job(
                {"acl": {"app": "unrelated"}, "content": {"dispatchState": "RUNNING"}}
            )
        )

    def test_backup_reads_all_pages_then_empty_completion_page(self):
        calls = []

        def get(path):
            calls.append(path)
            return [{"_key": str(i)} for i in range(500)] if len(calls) == 1 else []

        self.assertEqual(len(_collection_read(get)), 500)
        self.assertEqual(len(calls), 3)
        self.assertIn("skip=500", calls[-2])
        self.assertIn("skip=501", calls[-1])

    def test_short_page_from_a_server_side_cap_is_not_a_complete_backup(self):
        def get(path):
            from urllib.parse import parse_qs, urlsplit

            offset = int(parse_qs(urlsplit(path).query)["skip"][0])
            return [{"_key": str(i)} for i in range(offset, offset + 100)]

        with self.assertRaisesRegex(AssertionError, "completion proof"):
            _collection_read(get)

    def test_partial_duplicate_oversized_or_malformed_backup_refuses(self):
        for page in (
            {"results": []},
            [{"not_a_key": 1}],
            [{"_key": "same"}, {"_key": "same"}],
        ):
            with self.assertRaises(AssertionError):
                _collection_read(lambda _: page)
        with patch("tests.splunk.test_cisco_pruning.MAX_BACKUP_ROWS", 1):
            with self.assertRaisesRegex(AssertionError, "row bound"):
                _collection_read(lambda _: [{"_key": "one"}, {"_key": "two"}])
        with patch("tests.splunk.test_cisco_pruning.MAX_BACKUP_BYTES", 1):
            with self.assertRaisesRegex(AssertionError, "byte bound"):
                _collection_read(lambda _: [{"_key": "one"}])

    def test_failed_setup_without_backup_never_rewrites_collection(self):
        case = pruning.CiscoPruningTest(
            methodName="test_disabled_enabled_boundary_current_replay_and_idempotence"
        )
        case.collection_mutated = False
        case.original = None
        case.backup_verified = False
        case.macros = {}
        case.schedules = {}
        with (
            patch(
                "tests.splunk.test_cisco_pruning.lab._json",
                return_value={"entry": [{"content": {"definition": "0"}}]},
            ),
            patch.object(case, "_drain"),
            patch.object(
                case, "write", side_effect=AssertionError("unsafe collection rewrite")
            ),
        ):
            case.restore()

    def test_write_refuses_before_verified_backup_and_records_owner_only_artifact(self):
        case = pruning.CiscoPruningTest(
            methodName="test_disabled_enabled_boundary_current_replay_and_idempotence"
        )
        case.backup_verified = False
        case.original = None
        with self.assertRaisesRegex(AssertionError, "verified complete backup"):
            case.write([])
        with tempfile.TemporaryDirectory() as directory:
            case.evidence = Path(directory)
            metadata = case._record("before", [{"_key": "fixture"}])
            self.assertEqual(metadata["rows"], 1)
            self.assertEqual(
                (case.evidence / "before.json").stat().st_mode & 0o777, 0o600
            )


if __name__ == "__main__":
    unittest.main()
