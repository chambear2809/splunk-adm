from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.change_scenario_authorization import AuthorizationError
from tools.change_scenario_dispatch import DispatchOwnershipError
from tools.change_scenario_local_runner import (
    LocalRunnerError,
    build_physical_readback_query,
    execute_local_connected_scenario,
)
from tools.change_scenario_receipts import ReceiptContractError


class _FakeLocalSplunkAdapter:
    def __init__(
        self,
        *,
        task_id: str = "connected-local-01",
        sid: str = "1761600123.42",
        dispatch_state: str = "DONE",
        mutate_rows=None,
    ) -> None:
        self.task_id = task_id
        self.sid = sid
        self.dispatch_state = dispatch_state
        self.mutate_rows = mutate_rows
        self.ingested: list[dict[str, Any]] = []
        self.kvstore_checked = False
        self.dispatched_queries: list[str] = []

    def verify_task_owner(self, expected_task_id: str) -> dict[str, Any]:
        return {"task_id": self.task_id, "lab_name": "adm-connected-local-01"}

    def wait_kvstore_ready(self, timeout: float = 180.0) -> None:
        self.kvstore_checked = True

    def ingest_hec_events(self, raw_events: list[dict[str, Any]]) -> int:
        self.ingested.extend(raw_events)
        return len(raw_events)

    def dispatch_readback_search(
        self,
        *,
        spl: str,
        earliest: int | float,
        latest: int | float,
        expected_count: int,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        self.dispatched_queries.append(spl)
        # Return rows in reverse order (as Splunk does) with realistic _bkt/_cd/_indextime.
        rows = []
        for idx, raw in enumerate(reversed(self.ingested), start=1):
            payload = raw["event"]
            raw_text = (
                json.dumps(payload, sort_keys=True, separators=(",", ":"))
                if isinstance(payload, dict)
                else str(payload)
            )
            rows.append(
                {
                    "_bkt": f"{raw['index']}~0~ABCDEF01-2345-6789-ABCD-EF0123456789",
                    "_cd": f"0:{idx * 17}",
                    "adm_indextime": str(1761601000 + idx),
                    "adm_event_time": str(raw["time"]),
                    "index": raw["index"],
                    "source": raw["source"],
                    "sourcetype": raw["sourcetype"],
                    "host": raw["host"],
                    "_raw": raw_text,
                }
            )
        if self.mutate_rows is not None:
            rows = self.mutate_rows(rows)
        return {
            "sid": self.sid,
            "dispatch_state": self.dispatch_state,
            "dispatch_epoch": 1761601100,
            "caller": "admin",
            "rows": rows,
        }


class LocalConnectedScenarioRunnerTests(unittest.TestCase):
    EXECUTION_ID = "00000000-0000-4000-8000-000000000091"
    ANCHOR_EPOCH = 1761600000

    def _private_auth_path(self, root: Path, name: str = "auth.json") -> Path:
        private_dir = root.resolve() / "private"
        private_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(private_dir, 0o700)
        return private_dir / name

    def test_executes_and_binds_authorization_receipts_and_dotted_splunk_sid(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            adapter = _FakeLocalSplunkAdapter()
            result = execute_local_connected_scenario(
                "track-a-firewall",
                task_id="connected-local-01",
                execution_id=self.EXECUTION_ID,
                anchor_epoch=self.ANCHOR_EPOCH,
                authorization_path=auth_path,
                adapter=adapter,
                issued_epoch=1761600900,
            )
            self.assertTrue(adapter.kvstore_checked)
            self.assertEqual(result["sid"], "1761600123.42")
            self.assertEqual(result["row_count"], len(adapter.ingested))
            self.assertEqual(len(result["receipt_fingerprints"]), result["row_count"])
            self.assertTrue(
                result["qualification_scope"]["installed_local_splunk_synthetic_hec"]
            )
            self.assertFalse(
                result["qualification_scope"]["live_customer_sources_qualified"]
            )
            self.assertTrue(auth_path.exists())
            self.assertEqual(auth_path.stat().st_mode & 0o777, 0o600)

    def test_refuses_mismatched_task_owner_before_writing_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            adapter = _FakeLocalSplunkAdapter(task_id="foreign-task-99")
            with self.assertRaises(LocalRunnerError):
                execute_local_connected_scenario(
                    "track-a-firewall",
                    task_id="connected-local-01",
                    execution_id=self.EXECUTION_ID,
                    anchor_epoch=self.ANCHOR_EPOCH,
                    authorization_path=auth_path,
                    adapter=adapter,
                )
            self.assertFalse(auth_path.exists())
            self.assertEqual(adapter.ingested, [])

    def test_refuses_preexisting_authorization_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            auth_path.write_text("{}", encoding="utf-8")
            adapter = _FakeLocalSplunkAdapter()
            with self.assertRaises(AuthorizationError):
                execute_local_connected_scenario(
                    "track-a-firewall",
                    task_id="connected-local-01",
                    execution_id=self.EXECUTION_ID,
                    anchor_epoch=self.ANCHOR_EPOCH,
                    authorization_path=auth_path,
                    adapter=adapter,
                )

    def test_refuses_missing_physical_bucket_or_cd(self):
        def strip_bkt(rows):
            rows[0].pop("_bkt", None)
            return rows

        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            adapter = _FakeLocalSplunkAdapter(mutate_rows=strip_bkt)
            with self.assertRaises(ReceiptContractError):
                execute_local_connected_scenario(
                    "track-a-firewall",
                    task_id="connected-local-01",
                    execution_id=self.EXECUTION_ID,
                    anchor_epoch=self.ANCHOR_EPOCH,
                    authorization_path=auth_path,
                    adapter=adapter,
                )

    def test_refuses_duplicate_physical_identity(self):
        def dup_identity(rows):
            rows[1]["_bkt"] = rows[0]["_bkt"]
            rows[1]["_cd"] = rows[0]["_cd"]
            return rows

        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            adapter = _FakeLocalSplunkAdapter(mutate_rows=dup_identity)
            with self.assertRaises(ReceiptContractError):
                execute_local_connected_scenario(
                    "track-a-firewall",
                    task_id="connected-local-01",
                    execution_id=self.EXECUTION_ID,
                    anchor_epoch=self.ANCHOR_EPOCH,
                    authorization_path=auth_path,
                    adapter=adapter,
                )

    def test_refuses_tampered_payload(self):
        def tamper_payload(rows):
            rows[0]["_raw"] = '{"tampered": true}'
            return rows

        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            adapter = _FakeLocalSplunkAdapter(mutate_rows=tamper_payload)
            with self.assertRaises(ReceiptContractError):
                execute_local_connected_scenario(
                    "track-a-firewall",
                    task_id="connected-local-01",
                    execution_id=self.EXECUTION_ID,
                    anchor_epoch=self.ANCHOR_EPOCH,
                    authorization_path=auth_path,
                    adapter=adapter,
                )

    def test_refuses_invalid_traversal_sid(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = self._private_auth_path(Path(tmp))
            adapter = _FakeLocalSplunkAdapter(sid="1761600123..42")
            with self.assertRaises(DispatchOwnershipError):
                execute_local_connected_scenario(
                    "track-a-firewall",
                    task_id="connected-local-01",
                    execution_id=self.EXECUTION_ID,
                    anchor_epoch=self.ANCHOR_EPOCH,
                    authorization_path=auth_path,
                    adapter=adapter,
                )

    def test_query_builder_is_deterministic_and_bounded(self):
        manifest = {
            "entries": [
                {
                    "index": "netflow",
                    "source": "stream:netflow",
                    "sourcetype": "stream:netflow",
                    "host": "nf-1",
                    "source_time": 1000,
                }
            ]
        }
        q = build_physical_readback_query(manifest)
        self.assertEqual(q["earliest"], 940)
        self.assertEqual(q["latest"], 1060)
        self.assertEqual(
            q["sha256"], hashlib.sha256(q["literal"].encode("utf-8")).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
