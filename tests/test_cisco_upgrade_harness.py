"""Pure resume and duplicate-injection guards for the Cisco upgrade harness."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.cisco_contract_migration import Migration

from tests.splunk.test_cisco_upgrade import (
    _gap_injection_resume_action,
    _read_gap_evidence,
    _resume_staging,
    _upgrade_resume_route,
)


class CiscoUpgradeHarnessResumeTest(unittest.TestCase):
    @staticmethod
    def _expected_row():
        return Migration._v1_record_map(
            [
                {
                    "rollup_id": "a" * 64,
                    "adm_record": "conversation",
                    "records": 1,
                    "client_port_list": "61001",
                }
            ]
        )["a" * 64]

    class _FakeJournal:
        def __init__(self, value):
            self.value = value

        def read(self):
            return self.value

    class _FakeMigration:
        def __init__(self, journal):
            self.journal = CiscoUpgradeHarnessResumeTest._FakeJournal(journal)
            self.calls = []

        def _load(self):
            return self.journal.value

        def prepare(self, start, end):
            self.calls.append("prepare")

        def backfill(self):
            self.calls.append("backfill")

        def validate(self, scenario):
            self.calls.append("validate")
            return {"cutover_eligible": True, "status": "coverage_validated"}

    def test_phase_routes_do_not_repeat_staging(self):
        self.assertEqual(_upgrade_resume_route(None), "fresh")
        self.assertEqual(_upgrade_resume_route({"phase": "prepared"}), "backfill")
        self.assertEqual(_upgrade_resume_route({"phase": "backfilled"}), "validate")
        self.assertEqual(
            _upgrade_resume_route({"phase": "coverage_validated"}), "cutover"
        )
        self.assertEqual(
            _upgrade_resume_route({"phase": "cutover_in_progress"}), "cutover"
        )
        self.assertEqual(_upgrade_resume_route({"phase": "cutover"}), "rollback")
        self.assertEqual(
            _upgrade_resume_route({"phase": "rollback_in_progress"}), "rollback"
        )
        self.assertEqual(_upgrade_resume_route({"phase": "rolled_back"}), "terminal")

    def test_orchestration_calls_only_missing_stages(self):
        for phase, expected in (
            (None, ["prepare", "backfill", "validate"]),
            ("prepared", ["backfill", "validate"]),
            ("backfilled", ["validate"]),
            ("coverage_validated", []),
        ):
            journal = {} if phase is None else {"phase": phase}
            migration = self._FakeMigration(journal)
            _resume_staging(migration, 1, 2, {})
            self.assertEqual(migration.calls, expected)

    def test_gap_marker_fails_closed_without_evidence(self):
        for state in (
            "request_pending",
            "posted",
            "receipt_unknown",
            "receipt_confirmed",
        ):
            self.assertEqual(
                _gap_injection_resume_action({"gap_injection": {"state": state}}, None),
                "reconcile_required",
            )
        self.assertEqual(_gap_injection_resume_action({}, None), "inject")
        self.assertEqual(
            _gap_injection_resume_action(
                {"gap_injection": {"state": "unexpected"}}, None
            ),
            "reconcile_required",
        )
        self.assertEqual(
            _gap_injection_resume_action({}, {"state": "injected_waiting_rollback"}),
            "reuse",
        )

    def test_gap_evidence_requires_identity_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            path.write_text(
                json.dumps(
                    {
                        "state": "injected_waiting_rollback",
                        "migration_id": "m1",
                        "source": "gap",
                        "source_port": 61001,
                        "raw_index_receipt": 100,
                        "index_slice": [0, 300],
                        "rollup_id": "a" * 64,
                        "expected_row": self._expected_row(),
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            self.assertEqual(_read_gap_evidence(path, "m1")["source"], "gap")
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "other")
            value = json.loads(path.read_text(encoding="utf-8"))
            value.pop("migration_id")
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "m1")

    def test_gap_evidence_rejects_bad_receipt_and_rollup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            value = {
                "state": "injected_waiting_rollback",
                "migration_id": "m1",
                "source": "gap",
                "source_port": 61001,
                "raw_index_receipt": 301,
                "index_slice": [0, 300],
                "rollup_id": "not-a-rollup",
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "m1")

    def test_completed_gap_evidence_can_be_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            expected = self._expected_row()
            evidence = {
                "migration_id": "m1",
                "state": "recovered_and_selectors_restored",
                "source": "gap",
                "source_port": 61001,
                "raw_index_receipt": 100,
                "index_slice": [0, 300],
                "rollup_id": "a" * 64,
                "expected_row": expected,
                "retained_row": expected,
                "selectors_restored": True,
                "manual_recovery": {
                    "slice_key": "0:300",
                    "index_bounds": [0, 300],
                    "writer_sid": "manual_sid",
                },
            }
            path.write_text(json.dumps(evidence))
            path.chmod(0o600)
            self.assertEqual(_read_gap_evidence(path, "m1"), evidence)
            for change in (
                {"selectors_restored": False},
                {"manual_recovery": {}},
                {"retained_row": {}},
                {"index_slice": [0.0, 300]},
                {"index_slice": [1, 301]},
            ):
                with self.subTest(change=change):
                    path.write_text(json.dumps({**evidence, **change}))
                    with self.assertRaises(AssertionError):
                        _read_gap_evidence(path, "m1")

    def test_gap_evidence_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            os.mkfifo(path, 0o600)
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "m1")

    def test_gap_evidence_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "gap.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            link.symlink_to(target)
            with self.assertRaises(AssertionError):
                _read_gap_evidence(link, "m1")


if __name__ == "__main__":
    unittest.main()
