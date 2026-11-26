"""Installed local Splunk qualification for task-owned connected scenario execution."""

from __future__ import annotations

import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from tools.change_scenario_local_runner import (
    SplunkLabAdapter,
    execute_local_connected_scenario,
)

LAB_ENABLED = os.environ.get("ADM_LAB") == "1"
TASK_ID = os.environ.get("ADM_LAB_TASK", "")


@unittest.skipUnless(
    LAB_ENABLED and bool(TASK_ID),
    "Set ADM_LAB=1 and ADM_LAB_TASK to run installed connected scenario execution.",
)
class InstalledConnectedScenarioExecutionTests(unittest.TestCase):
    def test_track_a_firewall_physical_readback_and_ownership(self):
        execution_id = str(uuid.uuid4())
        # Anchor slightly in the past so all scenario offsets stay within Splunk's
        # indexed time bounds and never sit in the future.
        anchor_epoch = int(time.time()) - 1800
        with tempfile.TemporaryDirectory(prefix="adm-connected-auth-") as tmp:
            private_dir = Path(tmp).resolve() / "private"
            private_dir.mkdir(mode=0o700)
            os.chmod(private_dir, 0o700)
            auth_path = private_dir / "run-authorization.json"
            result = execute_local_connected_scenario(
                "track-a-firewall",
                task_id=TASK_ID,
                execution_id=execution_id,
                anchor_epoch=anchor_epoch,
                authorization_path=auth_path,
                adapter=SplunkLabAdapter(),
            )
            self.assertEqual(result["scenario_id"], "track-a-firewall")
            self.assertEqual(result["task_id"], TASK_ID)
            self.assertEqual(result["execution_id"], execution_id)
            self.assertGreater(result["row_count"], 0)
            self.assertEqual(len(result["receipt_fingerprints"]), result["row_count"])
            self.assertTrue(result["sid"])
            self.assertTrue(
                result["qualification_scope"]["installed_local_splunk_synthetic_hec"]
            )
            self.assertFalse(
                result["qualification_scope"]["live_customer_sources_qualified"]
            )


if __name__ == "__main__":
    unittest.main()
