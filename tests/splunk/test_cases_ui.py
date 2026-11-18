"""Opt-in rendered Firefox cases exercise, only in its disposable HTTPS lab."""

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402
import test_cases_endpoint as fixture  # noqa: E402
from web_session import RequestJournal  # noqa: E402

TASK = "cases-ui-20261117"
NAME = "adm-cases-ui-20261117"


@unittest.skipUnless(os.environ.get("ADM_LAB_CASES_UI") == "1", "explicit UI lab only")
class InstalledCasesUITest(fixture.InstalledCasesTest):
    def setUp(self):
        if lab.task_identity() != (TASK, NAME):
            raise RuntimeError("requires exact rendered cases lab")
        if os.environ.get("ADM_LAB_WEB_TLS") != "1":
            raise RuntimeError("requires verified Web HTTPS")
        self.journal = RequestJournal(os.environ["ADM_LAB_WEB_RECEIPT"])
        super().setUp()
        self.journal.fixture = {
            "role": self.role,
            "users": [name for name, _ in self.users],
            "initial_persistence": {
                key: self._config_snapshot[key]
                for key in ("mode", "platform", "capture_mode")
            },
        }
        self.journal._persist()

    def test_rendered_cases(self):
        lab._json(
            "POST",
            fixture.CONFIG,
            {
                "mode": "single_search_head",
                "platform": "enterprise",
                "capture_mode": "disabled",
            },
        )
        # Credentials cross an anonymous pipe only, never argv or evidence.
        payload = {
            "url": lab.WEB,
            "users": self.users,
            "role": self.role,
            "runtime": os.environ["ADM_LAB_UI_RUNTIME"],
            "output": os.environ["ADM_LAB_UI_OUTPUT"],
            "ca": str(lab.SECRETS) + ".tls/ca.pem",
            "browserExecutable": os.environ["ADM_LAB_FIREFOX"],
        }
        result = subprocess.run(
            [os.environ["ADM_LAB_NODE"], str(Path(__file__).with_name("cases_ui.mjs"))],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        # Never forward browser errors, which could include entered values.
        self.assertEqual(
            result.returncode, 0, "rendered cases failed; see private UI receipt"
        )
        receipt = json.loads((Path(payload["output"]) / "ui-receipt.json").read_text())
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["no_search_jobs"])


def load_tests(loader, _tests, _pattern):
    return loader.loadTestsFromName("test_rendered_cases", InstalledCasesUITest)
