"""Installed notes endpoint; only a task-owned disposable lab is accepted."""

import base64
import json
import os
import secrets
import sys
import subprocess
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402

ENDPOINT = "/servicesNS/nobody/splunk_adm/adm/investigations"
CONFIG = "/servicesNS/nobody/splunk_adm/configs/conf-adm_investigations/persistence"
TRANSPORT_CONFIG = (
    "/servicesNS/nobody/splunk_adm/configs/conf-adm_investigations/capture_transport"
)


def role_authority_payload():
    """Return the complete least-authority role update used by the fixture."""
    return {
        # Splunk's form adapter drops empty lists; an explicit empty string
        # preserves the no-import declaration on the wire.
        "imported_roles": "",
        "capabilities": ["adm_investigate"],
        "srchIndexesAllowed": "",
        "srchIndexesDefault": "",
        "srchFilter": "",
    }


def assert_exact_context(testcase, context, username, role):
    """Reject inherited admin or index authority before endpoint requests."""
    testcase.assertEqual(context.get("username"), username)
    testcase.assertEqual(context.get("roles"), [role])
    testcase.assertEqual(set(context.get("capabilities", [])), {"adm_investigate"})
    for key in ("srchIndexesAllowed", "srchIndexesDefault"):
        if key in context:
            testcase.assertEqual(set(context[key]), set())


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires task-owned lab")
class InstalledCasesTest(unittest.TestCase):
    def setUp(self):
        if lab.task_identity() is None:
            self.skipTest("requires distinct task-owned lab")
        lab.verify_target()
        # Snapshot before any mutation and register restoration immediately so
        # a later setup assertion cannot strand a task-owned lab in test mode.
        self._config_snapshot = self._config_content(
            CONFIG, ("mode", "platform", "capture_mode")
        )
        self._transport_snapshot = self._config_content(
            TRANSPORT_CONFIG, ("management_uri", "ca_file")
        )
        self.addCleanup(
            lab._json,
            "POST",
            CONFIG,
            {
                key: self._config_snapshot[key]
                for key in ("mode", "platform", "capture_mode")
            },
        )
        self.addCleanup(
            lab._json,
            "POST",
            TRANSPORT_CONFIG,
            {
                key: self._transport_snapshot[key]
                for key in ("management_uri", "ca_file")
            },
        )
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
                **role_authority_payload(),
            },
        )
        self.addCleanup(
            lab._json, "DELETE", "/services/authorization/roles/" + self.role
        )
        # Splunk may add implicit defaults during role creation; overwrite all
        # authority-bearing fields before creating users.
        lab._json(
            "POST",
            "/services/authorization/roles/" + self.role,
            role_authority_payload(),
        )
        role = lab._json("GET", "/services/authorization/roles/" + self.role)["entry"][
            0
        ]["content"]
        for key in (
            "imported_roles",
            "srchIndexesAllowed",
            "srchIndexesDefault",
            "srchFilter",
        ):
            self.assertIn(key, role)
        self.assertIn(role["imported_roles"], ("", []))
        self.assertIn(role["srchIndexesAllowed"], ("", []))
        self.assertIn(role["srchIndexesDefault"], ("", []))
        self.assertEqual(role["srchFilter"], "")
        self.assertEqual(set(role.get("capabilities", [])), {"adm_investigate"})
        for user, password in self.users:
            lab._json(
                "POST",
                "/services/authentication/users",
                {"name": user, "password": password, "roles": self.role},
            )
            self.addCleanup(
                lab._json, "DELETE", "/services/authentication/users/" + user
            )
        for user, password in self.users:
            authorization = base64.b64encode((user + ":" + password).encode()).decode()
            request = urllib.request.Request(
                lab.MGMT + "/services/authentication/current-context?output_mode=json",
                headers={"Authorization": "Basic " + authorization},
            )
            with lab.urlopen(request, timeout=30) as response:
                context = json.loads(response.read())["entry"][0]["content"]
            assert_exact_context(self, context, user, self.role)
        lab._json(
            "POST",
            CONFIG,
            {"mode": "disabled", "platform": "unqualified", "capture_mode": "disabled"},
        )

    @staticmethod
    def _config_content(path, required):
        try:
            content = lab._json("GET", path)["entry"][0]["content"]
            if not isinstance(content, dict) or not set(required) <= set(content):
                raise RuntimeError("incomplete configuration snapshot: " + path)
            return content
        except (KeyError, IndexError, TypeError, lab.LabError) as exc:
            raise RuntimeError(
                "cannot snapshot required configuration: " + path
            ) from exc

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
            response = lab.urlopen(request, timeout=30)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.loads(response.read())
        with response:
            return response.status, json.loads(response.read())

    def raw_request(self, method, path, body, *, user=0):
        """Send an already-encoded body to exercise the host's early bound."""
        name, password = self.users[user]
        request = urllib.request.Request(
            lab.MGMT + ENDPOINT + path + "?output_mode=json",
            method=method,
            headers={
                "Authorization": "Basic "
                + base64.b64encode((name + ":" + password).encode()).decode(),
                "Content-Type": "application/json",
            },
            data=body,
        )
        try:
            response = lab.urlopen(request, timeout=30)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.loads(response.read())
        with response:
            return response.status, json.loads(response.read())

    def test_oversized_raw_body_rejected_before_disabled_storage(self):
        status, payload = self.raw_request(
            "POST", "/cases", b"{" + b"x" * 128001 + b"}"
        )
        self.assertEqual((413, {"error": "body_too_large"}), (status, payload))
        status, capability = self.request("GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertFalse(capability["available"])

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
        original = case["entries"][0]
        revision = {
            "expected_revision": 2,
            "item": {
                "type": "note",
                "text": "Revised investigator note",
                "supersedes_entry_id": original["id"],
            },
        }
        status, case = self.request("POST", path + "/entries", revision, "revise")
        self.assertEqual(status, 200)
        self.assertEqual(case["entries"][0], original)
        self.assertEqual(case["entries"][1]["supersedes_entry_id"], original["id"])
        self.assertEqual(
            case, self.request("POST", path + "/entries", revision, "revise")[1]
        )
        self.assertEqual(
            self.request(
                "POST",
                path + "/entries",
                {**revision, "expected_revision": 3},
                "branch",
            )[0],
            409,
        )
        status, case = self.request(
            "POST",
            path + "/share",
            {"expected_revision": 3, "member": self.users[1][0], "grant": True},
            "share",
        )
        self.assertEqual(200, status)
        self.assertEqual(200, self.request("GET", path + "/export", user=1)[0])
        self.assertEqual(
            200,
            self.request(
                "POST",
                path + "/share",
                {"expected_revision": 4, "member": self.users[1][0], "grant": False},
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
                    "expected_revision": 5,
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
            200, self.request("DELETE", path, {"expected_revision": 5}, "delete")[0]
        )

    @unittest.skipUnless(
        os.environ.get("ADM_LAB_EXPECT_UNSUPPORTED_CAPTURE") == "1",
        "explicit unsupported-runtime qualification only",
    )
    def test_unsupported_runtime_preflight_keeps_notes_without_job_intents(self):
        lab._json(
            "POST",
            "/servicesNS/nobody/splunk_adm/configs/conf-adm_investigations/capture_transport",
            {
                "management_uri": "https://127.0.0.1:8089",
                "ca_file": "/opt/splunk/etc/auth/adm_lab_tls/ca.pem",
            },
        )
        lab._json(
            "POST",
            CONFIG,
            {
                "mode": "single_search_head",
                "platform": "enterprise",
                "capture_mode": "reproducible_qualified_v1",
            },
        )
        status, capability = self.request("GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertTrue(capability["available"])
        self.assertFalse(capability["evidenceWrites"])
        self.assertEqual(capability["mode"], "notes_only")
        status, case = self.request(
            "POST",
            "/cases",
            {
                "schema_version": 1,
                "title": "Unsupported helper notes",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-01T01:00:00Z",
                },
            },
            "runtime-case",
        )
        self.assertEqual(status, 201)
        status, case = self.request(
            "POST",
            "/cases/" + case["id"] + "/entries",
            {
                "expected_revision": 1,
                "item": {"type": "note", "text": "Notes remain available"},
            },
            "runtime-note",
        )
        self.assertEqual(status, 200)
        self.assertEqual(case["entries"][0]["text"], "Notes remain available")
        lab.verify_target()
        container = lab.lab_tls.read_container(lab.SECRETS, lab.task_identity())
        code = "import json,os,sys; sys.path.insert(0,'/opt/splunk/etc/apps/splunk_adm/bin'); from adm_cases_lib.transport import SupervisedTransport,TransportError; t=SupervisedTransport('synthetic-token','https://127.0.0.1:8089','/opt/splunk/etc/auth/adm_lab_tls/ca.pem'); ready=False\ntry: ready=t.preflight()\nexcept TransportError: pass\nassert not ready; assert not os.path.exists('/opt/splunk/var/lib/splunk/splunk_adm_investigations/capture_jobs.sqlite'); print(json.dumps({'preflight_ready':ready,'job_ledger_absent':True}))"
        done = subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "41812:41812",
                container,
                "/opt/splunk/bin/splunk",
                "cmd",
                "python3",
                "-c",
                code,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        )
        self.assertEqual(
            json.loads(done.stdout),
            {"preflight_ready": False, "job_ledger_absent": True},
        )
