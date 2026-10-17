"""Co-installation checks; these do not qualify live vendor collection."""

import json
import os
from pathlib import Path
import sys
import unittest
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PACKAGES = {
    "cisco-catalyst-app": "4.0.20",
    "TA_cisco_catalyst": "4.0.50",
    "splunk_app_stream_ipfix_cisco_hsl": "4.0.0",
    "Splunk_TA_cisco_meraki": "3.5.0",
}


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoVendorAppLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab

    def test_vendor_packages_are_separate_from_atlas(self):
        for app, version in PACKAGES.items():
            with self.subTest(app=app):
                record = self.lab._json(
                    "GET", "/services/apps/local/" + quote(app, safe="")
                )["entry"][0]
                self.assertEqual(record["name"], app)
                self.assertEqual(record["content"]["version"], version)
                self.assertFalse(record["content"]["disabled"])

    def test_vendor_dashboard_definitions_are_available(self):
        payload = self.lab._json(
            "GET", "/servicesNS/nobody/cisco-catalyst-app/data/ui/views?count=0"
        )
        rows = payload["entry"]
        self.assertGreater(len(rows), 0)
        self.assertEqual(int(payload["paging"]["total"]), len(rows))
        self.assertTrue(any("meraki" in row["name"].lower() for row in rows))
        self.assertTrue(any("sdwan" in row["name"].lower() for row in rows))

    def test_vendor_writers_remain_disabled_in_static_input_lab(self):
        payload = self.lab._json(
            "GET", "/servicesNS/nobody/cisco-catalyst-app/saved/searches?count=0"
        )
        rows = [
            row for row in payload["entry"] if row["acl"]["app"] == "cisco-catalyst-app"
        ]
        self.assertGreater(len(rows), 0)
        for row in rows:
            with self.subTest(name=row["name"]):
                self.assertTrue(row["content"]["disabled"])
                self.assertFalse(row["content"]["is_scheduled"])

    def test_vendor_source_macros_accept_the_selected_source_types(self):
        sys.path.insert(0, str(ROOT / "tools"))
        from capture_networking_fixtures import require_complete

        data = {
            "search": "search `cisco_catalyst_app_index` `cisco_catalyst_app_sourcetypes` | stats count by sourcetype",
            "exec_mode": "blocking",
            "earliest_time": "0",
            "latest_time": "+1d",
        }
        with self.lab._mgmt(
            "POST",
            "/servicesNS/admin/cisco-catalyst-app/search/v2/jobs?output_mode=json",
            data,
            900,
        ) as response:
            sid = json.load(response)["sid"]
        status = self.lab._wait_job(sid)
        payload = self.lab._json(
            "GET", f"/services/search/v2/jobs/{sid}/results?count=0"
        )
        rows = payload.get("results", [])
        status["messages"] = status.get("messages", []) + payload.get("messages", [])
        require_complete(status, rows)
        manifest = json.loads(
            (ROOT / "fixtures/raw-networking/capture-manifest.json").read_text()
        )
        expected = {
            name: count
            for name, count in manifest["sourcetype_events"].items()
            if name.startswith(("cisco:dnac", "meraki:")) or name == "stream:netflow"
        }
        self.assertGreaterEqual(len(expected), 3)
        actual = {row["sourcetype"]: int(row["count"]) for row in rows}
        for name, count in expected.items():
            with self.subTest(sourcetype=name):
                self.assertGreaterEqual(actual.get(name, 0), count)
