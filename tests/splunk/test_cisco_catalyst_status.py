"""Live regression coverage for Catalyst client attachment status."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MACROS = ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"
sys.path.insert(0, str(ROOT / "tools"))
from lab_lock import LabLock  # noqa: E402


def _macro(text: str, name: str) -> str:
    match = re.search(rf"(?ms)^\[{re.escape(name)}\]\n.*?(?=^\[|\Z)", text)
    if not match:
        raise AssertionError(f"missing macro stanza: {name}")
    return match.group(0)


def _attachment_status_expression() -> str:
    history = _macro(
        MACROS.read_text(encoding="utf-8"),
        "adm_network_client_history_observations",
    )
    match = re.search(
        r"attachment_status=(case\(.*?\)), attachment_basis=",
        history,
    )
    if not match:
        raise AssertionError("Catalyst attachment_status case expression is missing")
    return match.group(1)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoCatalystStatusLabTest(unittest.TestCase):
    """Evaluate the shipped Catalyst expression against synthetic rows only."""

    @classmethod
    def setUpClass(cls) -> None:
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")

    def test_attachment_status_requires_complete_connected_wired_switch(self):
        import lab

        rows = [
            {
                "case_name": "complete",
                "adm_raw_client_type": "wired",
                "connectionStatus": "connected",
                "connected_device_type": "Switch",
                "interface": "GigabitEthernet1/0/1",
            },
            {
                "case_name": "disconnected",
                "adm_raw_client_type": "wired",
                "connectionStatus": "disconnected",
                "connected_device_type": "Switch",
                "interface": "GigabitEthernet1/0/1",
            },
        ]
        missing_fields = (
            "adm_raw_client_type",
            "connectionStatus",
            "connected_device_type",
            "interface",
        )
        for field in missing_fields:
            rows.append(
                {
                    "case_name": f"missing_{field}",
                    "adm_raw_client_type": "wired",
                    "connectionStatus": "connected",
                    "connected_device_type": "Switch",
                    "interface": "GigabitEthernet1/0/1",
                }
            )
            rows[-1].pop(field)
            rows.append(
                {
                    "case_name": f"empty_{field}",
                    "adm_raw_client_type": "wired",
                    "connectionStatus": "connected",
                    "connected_device_type": "Switch",
                    "interface": "GigabitEthernet1/0/1",
                }
            )
            rows[-1][field] = ""
            rows.append(
                {
                    "case_name": f"null_{field}",
                    "adm_raw_client_type": "wired",
                    "connectionStatus": "connected",
                    "connected_device_type": "Switch",
                    "interface": "GigabitEthernet1/0/1",
                }
            )
            rows[-1][field] = None

        payload = json.dumps(json.dumps(rows, separators=(",", ":")))
        query = (
            f"| makeresults format=json data={payload} "
            f"| eval attachment_status={_attachment_status_expression()} "
            "| table case_name attachment_status"
        )
        result = lab.search(query, "0", "+10y")
        statuses = {row["case_name"]: row.get("attachment_status") for row in result}

        self.assertEqual(len(result), len(rows))
        self.assertEqual(set(statuses), {row["case_name"] for row in rows})
        self.assertEqual(statuses["complete"], "observed_snapshot")
        self.assertEqual(statuses["disconnected"], "disconnected_snapshot")
        for name, status in statuses.items():
            if name not in {"complete", "disconnected"}:
                self.assertIn(
                    status,
                    {
                        "unsupported_client_type",
                        "disconnected_snapshot",
                        "incomplete_snapshot",
                    },
                    name,
                )
