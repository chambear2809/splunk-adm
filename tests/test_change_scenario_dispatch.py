from __future__ import annotations

import copy
import hashlib
import unittest

from tools.change_scenario_dispatch import (
    DispatchOwnershipError,
    bind_local_readback,
    verify_local_readback_ownership,
)
from tools.change_correlation.contracts import canonical_json


class DispatchOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "scenario_id": "track-b-fabric",
            "execution_id": "00000000-0000-4000-8000-000000000071",
        }
        self.plan["plan_sha256"] = hashlib.sha256(
            canonical_json({key: value for key, value in self.plan.items()})
        ).hexdigest()
        self.kwargs = {
            "task_id": "scenario-task-01",
            "sid": "job_123",
            "query_literal": "search index=atlas_changes | head 1",
            "dispatch_epoch": 1900000200,
            "readback": {
                "complete": True,
                "sid": "job_123",
                "task_id": "scenario-task-01",
                "plan_sha256": self.plan["plan_sha256"],
                "rows": [{"_indextime": 1900000201, "record_id": "r1"}],
                "receipt_fingerprints": [hashlib.sha256(canonical_json({"_indextime": 1900000201, "record_id": "r1"})).hexdigest()],
                "index_time_bounds": {"earliest": 1900000201, "latest": 1900000201},
            },
            "expected_task_id": "scenario-task-01",
            "expected_plan_sha256": self.plan["plan_sha256"],
            "expected_execution_id": "00000000-0000-4000-8000-000000000071",
            "expected_sid": "job_123",
            "expected_query_sha256": hashlib.sha256(b"search index=atlas_changes | head 1").hexdigest(),
            "approved_query_sha256": {hashlib.sha256(b"search index=atlas_changes | head 1").hexdigest()},
        }

    def test_binds_task_sid_plan_and_physical_receipt(self):
        record = bind_local_readback(self.plan, **self.kwargs)
        expected = {"row_count": 1, "rows_sha256": hashlib.sha256(canonical_json([{"_indextime": 1900000201, "record_id": "r1"}])).hexdigest(), "receipt_fingerprints": self.kwargs["readback"]["receipt_fingerprints"], "index_time_bounds": {"earliest": 1900000201, "latest": 1900000201}}
        self.assertEqual(verify_local_readback_ownership(record, expected_task_id="scenario-task-01", expected_plan_sha256=self.plan["plan_sha256"], expected_execution_id=self.kwargs["expected_execution_id"], expected_sid="job_123", expected_query_sha256=self.kwargs["expected_query_sha256"], approved_query_sha256=self.kwargs["approved_query_sha256"], expected_readback=expected), record)

    def test_rejects_cross_task_or_plan_readback(self):
        bad = copy.deepcopy(self.kwargs)
        bad["readback"]["task_id"] = "other-task"
        with self.assertRaises(DispatchOwnershipError):
            bind_local_readback(self.plan, **bad)

    def test_rejects_missing_or_mismatched_physical_receipts(self):
        bad = copy.deepcopy(self.kwargs)
        bad["readback"]["receipt_fingerprints"] = []
        with self.assertRaises(DispatchOwnershipError):
            bind_local_readback(self.plan, **bad)

    def test_rejects_rehashed_record_without_owner_integrity(self):
        record = bind_local_readback(self.plan, **self.kwargs)
        record["task_id"] = "other-task"
        with self.assertRaises(DispatchOwnershipError):
            verify_local_readback_ownership(record, expected_task_id="scenario-task-01", expected_plan_sha256=self.plan["plan_sha256"], expected_execution_id=self.kwargs["expected_execution_id"], expected_sid="job_123", expected_query_sha256=self.kwargs["expected_query_sha256"], approved_query_sha256=self.kwargs["approved_query_sha256"], expected_readback={})

    def test_rejects_rehashed_foreign_execution_plan(self):
        foreign = copy.deepcopy(self.plan)
        foreign["execution_id"] = "00000000-0000-4000-8000-000000000072"
        foreign["plan_sha256"] = hashlib.sha256(
            canonical_json({key: value for key, value in foreign.items() if key != "plan_sha256"})
        ).hexdigest()
        with self.assertRaises(DispatchOwnershipError):
            bind_local_readback(foreign, **self.kwargs)

    def test_rehashed_sid_and_query_substitutions_fail(self):
        record = bind_local_readback(self.plan, **self.kwargs)
        sid_forged = copy.deepcopy(record)
        sid_forged["dispatch"]["sid"] = "job_foreign"
        sid_forged["readback"]["sid"] = "job_foreign"
        sid_forged["ownership_sha256"] = hashlib.sha256(
            canonical_json({key: value for key, value in sid_forged.items() if key != "ownership_sha256"})
        ).hexdigest()
        expected = {"row_count": 1, "rows_sha256": hashlib.sha256(canonical_json([{"_indextime": 1900000201, "record_id": "r1"}])).hexdigest(), "receipt_fingerprints": self.kwargs["readback"]["receipt_fingerprints"], "index_time_bounds": {"earliest": 1900000201, "latest": 1900000201}}
        with self.assertRaises(DispatchOwnershipError):
            verify_local_readback_ownership(sid_forged, expected_task_id="scenario-task-01", expected_plan_sha256=self.plan["plan_sha256"], expected_execution_id=self.kwargs["expected_execution_id"], expected_sid="job_123", expected_query_sha256=self.kwargs["expected_query_sha256"], approved_query_sha256=self.kwargs["approved_query_sha256"], expected_readback=expected)
        query_forged = copy.deepcopy(record)
        query_forged["dispatch"]["query_sha256"] = "c" * 64
        query_forged["ownership_sha256"] = hashlib.sha256(
            canonical_json({key: value for key, value in query_forged.items() if key != "ownership_sha256"})
        ).hexdigest()
        with self.assertRaises(DispatchOwnershipError):
            verify_local_readback_ownership(query_forged, expected_task_id="scenario-task-01", expected_plan_sha256=self.plan["plan_sha256"], expected_execution_id=self.kwargs["expected_execution_id"], expected_sid="job_123", expected_query_sha256=self.kwargs["expected_query_sha256"], approved_query_sha256=self.kwargs["approved_query_sha256"], expected_readback=expected)

