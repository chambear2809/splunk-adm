"""Installed notes endpoint; only a task-owned disposable lab is accepted."""

import base64
import json
import os
import secrets
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402

ENDPOINT = "/servicesNS/nobody/splunk_adm/adm/investigations"
CONFIG = "/servicesNS/nobody/splunk_adm/configs/conf-adm_investigations/persistence"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires task-owned lab")
class InstalledCasesTest(unittest.TestCase):
    def setUp(self):
        if lab.task_identity() is None:
            self.skipTest("requires distinct task-owned lab")
        lab.verify_target()
        suffix = secrets.token_hex(5)
        self.role = "atlas_cases_" + suffix
        self.users = [
            ("atlas_case_" + suffix + tail, secrets.token_urlsafe(24))
            for tail in ("a", "b")
        ]
        lab._json(
            "POST",
            "/services/authorization/roles",
            {
                "name": self.role,
                "imported_roles": "user",
                "capabilities": "adm_investigate",
            },
        )
        for user, password in self.users:
            lab._json(
                "POST",
                "/services/authentication/users",
                {"name": user, "password": password, "roles": self.role},
            )
        lab._json("POST", CONFIG, {"mode": "disabled", "platform": "unqualified"})

    def request(self, method, path, body=None, key=None, user=0):
        name, password = self.users[user]
        headers = {
            "Authorization": "Basic "
            + base64.b64encode((name + ":" + password).encode()).decode()
        }
        if key:
            headers["Idempotency-Key"] = key
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            lab.MGMT + ENDPOINT + path + "?output_mode=json",
            method=method,
            headers=headers,
            data=data,
        )
        try:
            response = urllib.request.urlopen(request, context=lab._CTX, timeout=30)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.loads(response.read())
        with response:
            return response.status, json.loads(response.read())

    def test_private_notes_retry_sharing_revocation_and_disabled_default(self):
        status, info = self.request("GET", "/capabilities")
        self.assertEqual(200, status)
        self.assertFalse(info["available"])
        lab._json(
            "POST", CONFIG, {"mode": "single_search_head", "platform": "enterprise"}
        )
        status, info = self.request("GET", "/capabilities")
        self.assertEqual(200, status)
        self.assertTrue(info["available"])
        body = {
            "schema_version": 1,
            "title": "Installed notes",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"},
        }
        status, case = self.request("POST", "/cases", body, "create")
        self.assertEqual(201, status)
        path = "/cases/" + case["id"]
        self.assertEqual(case, self.request("POST", "/cases", body, "create")[1])
        self.assertEqual(403, self.request("GET", path, user=1)[0])
        status, case = self.request(
            "POST",
            path + "/entries",
            {
                "expected_revision": 1,
                "item": {"type": "note", "text": "Captured investigator note"},
            },
            "note",
        )
        self.assertEqual(200, status)
        self.assertEqual(1, len(case["entries"]))
        status, case = self.request(
            "POST",
            path + "/share",
            {"expected_revision": 2, "member": self.users[1][0], "grant": True},
            "share",
        )
        self.assertEqual(200, status)
        self.assertEqual(200, self.request("GET", path + "/export", user=1)[0])
        self.assertEqual(
            200,
            self.request(
                "POST",
                path + "/share",
                {"expected_revision": 3, "member": self.users[1][0], "grant": False},
                "revoke",
            )[0],
        )
        self.assertEqual(403, self.request("GET", path + "/export", user=1)[0])
        self.assertEqual(
            403,
            self.request(
                "POST",
                path + "/captures",
                {
                    "expected_revision": 4,
                    "item": {
                        "label": "source",
                        "captured_at": "2026-01-01T02:00:00Z",
                        "data": {},
                    },
                },
                "capture",
            )[0],
        )
        self.assertEqual(
            200, self.request("DELETE", path, {"expected_revision": 4}, "delete")[0]
        )
