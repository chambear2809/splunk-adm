from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from tools.change_correlation.contracts import canonical_json
from tools.change_scenario_authorization import (
    AuthorizationError,
    issue_run_authorization,
    verify_run_authorization,
    write_private_authorization,
)


class RunAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "scenario_id": "track-b-fabric",
            "execution_id": "00000000-0000-4000-8000-000000000071",
        }
        self.plan["plan_sha256"] = hashlib.sha256(canonical_json(self.plan)).hexdigest()
        self.query = {
            "name": "graph.baseline",
            "sha256": "b" * 64,
            "earliest": 1900000200,
            "latest": 1900000500,
        }

    def test_issue_verify_and_private_write(self):
        auth = issue_run_authorization(
            self.plan,
            task_id="scenario-task-01",
            approved_queries=[self.query],
            issued_epoch=1900000000,
        )
        self.assertEqual(
            verify_run_authorization(
                auth,
                expected_task_id="scenario-task-01",
                expected_plan_sha256=self.plan["plan_sha256"],
                expected_execution_id=self.plan["execution_id"],
                expected_queries=[self.query],
            ),
            auth,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "authorization.json"
            write_private_authorization(path, auth)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rehashed_foreign_task_or_window_fails(self):
        auth = issue_run_authorization(
            self.plan,
            task_id="scenario-task-01",
            approved_queries=[self.query],
            issued_epoch=1900000000,
        )
        forged = copy.deepcopy(auth)
        forged["task_id"] = "other-task"
        forged["authorization_sha256"] = hashlib.sha256(
            canonical_json(
                {k: v for k, v in forged.items() if k != "authorization_sha256"}
            )
        ).hexdigest()
        with self.assertRaises(AuthorizationError):
            verify_run_authorization(
                forged,
                expected_task_id="scenario-task-01",
                expected_plan_sha256=self.plan["plan_sha256"],
                expected_execution_id=self.plan["execution_id"],
                expected_queries=[self.query],
            )

    def test_rehashed_query_window_fails_against_independent_approval(self):
        auth = issue_run_authorization(
            self.plan,
            task_id="scenario-task-01",
            approved_queries=[self.query],
            issued_epoch=1900000000,
        )
        forged = copy.deepcopy(auth)
        forged["approved_queries"][0]["latest"] += 1
        forged["authorization_sha256"] = hashlib.sha256(
            canonical_json(
                {k: v for k, v in forged.items() if k != "authorization_sha256"}
            )
        ).hexdigest()
        with self.assertRaises(AuthorizationError):
            verify_run_authorization(
                forged,
                expected_task_id="scenario-task-01",
                expected_plan_sha256=self.plan["plan_sha256"],
                expected_execution_id=self.plan["execution_id"],
                expected_queries=[self.query],
            )

    def test_symlink_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            target.mkdir()
            (root / "link").symlink_to(target, target_is_directory=True)
            auth = issue_run_authorization(
                self.plan,
                task_id="scenario-task-01",
                approved_queries=[self.query],
                issued_epoch=1900000000,
            )
            with self.assertRaises(AuthorizationError):
                write_private_authorization(root / "link" / "authorization.json", auth)

    def test_partial_write_is_completed_and_fstat_checked(self):
        auth = issue_run_authorization(
            self.plan,
            task_id="scenario-task-01",
            approved_queries=[self.query],
            issued_epoch=1900000000,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "authorization.json"
            import tools.change_scenario_authorization as module

            original = module.os.write
            calls = []

            def partial(fd, data):
                calls.append(len(data))
                return original(fd, data[: max(1, len(data) // 2)])

            with patch.object(module.os, "write", side_effect=partial):
                write_private_authorization(path, auth)
            self.assertGreater(len(calls), 1)

    def test_invalid_serialization_does_not_create_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "authorization.json"
            with self.assertRaises(Exception):
                write_private_authorization(path, {"invalid": {1, 2}})
            self.assertFalse(path.exists())
